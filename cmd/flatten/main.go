package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/pkoukk/tiktoken-go"
	"github.com/spf13/cobra"
)

// Version information (set by build process)
var version = "dev"

// FileEntry represents a file in the flattened structure
type FileEntry struct {
	Path     string
	IsDir    bool
	Size     int64
	Mode     fs.FileMode
	ModTime  int64
	Content  []byte
	Tokens   int
	Children []*FileEntry
}

// FileHash is used for deduplication
type FileHash struct {
	Path    string
	Hash    string
	Content []byte
}

// Flags
var (
	includeGitIgnore    bool
	includeGit          bool
	includeBin          bool
	includeLocks        bool
	noFileDeduplication bool

	showLastUpdated bool
	showFileMode    bool
	showFileSize    bool
	showMimeType    bool
	showSymlinks    bool
	showOwnership   bool
	showChecksum    bool
	showAllMetadata bool
	showTotalSize   bool

	showTokens  bool
	tokensModel string

	includePatterns []string
	excludePatterns []string

	markdownDelimiter string
	dryRun            bool

	// commands to run after flattening
	commands []string
)

// Available markdown delimiters in order of preference for auto-detection
var availableDelimiters = []string{"```", "~~~", "`````", "~~~~~", "~~~~~~~~~~~"}

// detectBestDelimiter scans all files and returns the first delimiter that's not used
func detectBestDelimiter(root *FileEntry) string {
	usedDelimiters := make(map[string]bool)

	// Recursively scan all files for delimiter usage
	scanForDelimiters(root, usedDelimiters)

	// Return the first delimiter that's not used
	for _, delimiter := range availableDelimiters {
		if !usedDelimiters[delimiter] {
			return delimiter
		}
	}

	// Fallback to the longest delimiter if all are used
	return availableDelimiters[len(availableDelimiters)-1]
}

// scanForDelimiters recursively scans files for delimiter usage
func scanForDelimiters(entry *FileEntry, usedDelimiters map[string]bool) {
	if !entry.IsDir {
		content := string(entry.Content)
		for _, delimiter := range availableDelimiters {
			if strings.Contains(content, delimiter) {
				usedDelimiters[delimiter] = true
			}
		}
	} else {
		for _, child := range entry.Children {
			scanForDelimiters(child, usedDelimiters)
		}
	}
}

// sumTokens recurses over a directory entry and sums the tokens of all children
func sumTokens(entry *FileEntry) int {
	if !entry.IsDir {
		return entry.Tokens
	}
	var total int
	for _, child := range entry.Children {
		total += sumTokens(child)
	}
	entry.Tokens = total
	return total
}

func loadDirectory(path string, filter *Filter, tokenizer *tiktoken.Tiktoken) (*FileEntry, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat path %s: %w", path, err)
	}
	if !filter.ShouldInclude(info, path) {
		return nil, nil
	}
	entry := &FileEntry{
		Path:     path,
		IsDir:    info.IsDir(),
		Size:     info.Size(),
		Mode:     info.Mode(),
		ModTime:  info.ModTime().Unix(),
		Children: make([]*FileEntry, 0),
	}
	if !info.IsDir() {
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read file %s: %w", path, err)
		}
		entry.Content = content
		if tokenizer != nil {
			toks := tokenizer.Encode(string(content), nil, nil)
			entry.Tokens = len(toks)
		}
		return entry, nil
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory %s: %w", path, err)
	}
	for _, item := range entries {
		childPath := filepath.Join(path, item.Name())
		child, err := loadDirectory(childPath, filter, tokenizer)
		if err != nil {
			return nil, err
		}
		if child != nil {
			entry.Children = append(entry.Children, child)
		}
	}
	return entry, nil
}

func loadDirectoryDryRun(path string, filter *Filter) (*FileEntry, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat path %s: %w", path, err)
	}
	if !filter.ShouldInclude(info, path) {
		return nil, nil
	}
	entry := &FileEntry{
		Path:     path,
		IsDir:    info.IsDir(),
		Size:     info.Size(),
		Mode:     info.Mode(),
		ModTime:  info.ModTime().Unix(),
		Children: make([]*FileEntry, 0),
		Content:  nil, // Don't read file content in dry-run mode
		Tokens:   0,   // No token counting in dry-run mode
	}
	if !info.IsDir() {
		return entry, nil
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory %s: %w", path, err)
	}
	for _, item := range entries {
		childPath := filepath.Join(path, item.Name())
		child, err := loadDirectoryDryRun(childPath, filter)
		if err != nil {
			return nil, err
		}
		if child != nil {
			entry.Children = append(entry.Children, child)
		}
	}
	return entry, nil
}

func getTotalFiles(entry *FileEntry) int {
	if !entry.IsDir {
		return 1
	}
	total := 0
	for _, child := range entry.Children {
		total += getTotalFiles(child)
	}
	return total
}

func getTotalSize(entry *FileEntry) int64 {
	if !entry.IsDir {
		return entry.Size
	}
	var total int64
	for _, child := range entry.Children {
		total += getTotalSize(child)
	}
	return total
}

func renderDirTree(entry *FileEntry, prefix string, isLast bool, showTokens bool) string {
	var sb strings.Builder
	if entry.Path != "." {
		marker := "├── "
		if isLast {
			marker = "└── "
		}
		// For the root's direct children (top-level dirs), show full path
		// For everything else, show just the base name
		name := entry.Path
		if !strings.HasPrefix(prefix, "│") && !strings.HasPrefix(prefix, " ") {
			// This is a top-level directory, keep full path
		} else {
			// This is a child, show only base name
			name = filepath.Base(entry.Path)
		}
		if showTokens {
			name = fmt.Sprintf("%s (%d tokens)", name, entry.Tokens)
		}
		sb.WriteString(prefix + marker + name + "\n")
	}
	if entry.IsDir {
		newPrefix := prefix
		if entry.Path != "." {
			if isLast {
				newPrefix += "    "
			} else {
				newPrefix += "│   "
			}
		}
		for i, child := range entry.Children {
			isLastChild := i == len(entry.Children)-1
			sb.WriteString(renderDirTree(child, newPrefix, isLastChild, showTokens))
		}
	}
	return sb.String()
}

func calculateFileHash(content []byte) string {
	if content == nil {
		return ""
	}
	hasher := sha256.New()
	hasher.Write(content)
	return hex.EncodeToString(hasher.Sum(nil))
}

func printFlattenedOutput(entry *FileEntry, w *strings.Builder, fileHashes map[string]*FileHash, showTokens bool, delimiter string) {
	if !entry.IsDir {
		w.WriteString(fmt.Sprintf("\n- path: %s\n", entry.Path))
		if showAllMetadata || showLastUpdated {
			w.WriteString(fmt.Sprintf("- last updated: %s\n", time.Unix(entry.ModTime, 0).Format(time.RFC3339)))
		}
		if showAllMetadata || showFileMode {
			w.WriteString(fmt.Sprintf("- mode: %s\n", entry.Mode.String()))
		}
		if showAllMetadata || showFileSize {
			w.WriteString(fmt.Sprintf("- size: %d bytes\n", entry.Size))
		}
		if showAllMetadata || showMimeType {
			mimeType := guessMimeType(entry.Path, entry.Content)
			w.WriteString(fmt.Sprintf("- mime-type: %s\n", mimeType))
		}
		if showAllMetadata || (showSymlinks && entry.Mode&os.ModeSymlink != 0) {
			target, err := os.Readlink(entry.Path)
			if err == nil {
				w.WriteString(fmt.Sprintf("- symlink-target: %s\n", target))
			}
		}
		if showAllMetadata || showOwnership {
			getOwnershipInfo(entry.Path, w)
		}
		if showAllMetadata || showChecksum {
			hash := calculateFileHash(entry.Content)
			w.WriteString(fmt.Sprintf("- sha256: %s\n", hash))
		}
		if showTokens {
			w.WriteString(fmt.Sprintf("- tokens: %d\n", entry.Tokens))
		}
		if noFileDeduplication {
			w.WriteString(fmt.Sprintf("- content:\n%s\n%s\n%s\n", delimiter, string(entry.Content), delimiter))
			return
		}
		hash := calculateFileHash(entry.Content)
		if existing, exists := fileHashes[hash]; exists {
			w.WriteString(fmt.Sprintf("- content: Contents are identical to %s\n", existing.Path))
		} else {
			fileHashes[hash] = &FileHash{Path: entry.Path, Hash: hash, Content: entry.Content}
			w.WriteString(fmt.Sprintf("- content:\n%s\n%s\n%s\n", delimiter, string(entry.Content), delimiter))
		}
		return
	}
	if showTokens {
		w.WriteString(fmt.Sprintf("\n- path: %s\n", entry.Path))
		w.WriteString(fmt.Sprintf("- dir tokens: %d\n", entry.Tokens))
	}
	for _, child := range entry.Children {
		printFlattenedOutput(child, w, fileHashes, showTokens, delimiter)
	}
}

// CommandResult captures the outcome of running a single shell command
type CommandResult struct {
	Command   string
	StartTime time.Time
	EndTime   time.Time
	Duration  time.Duration
	ExitCode  int
	Stdout    string
	Stderr    string
}

func buildShellCommand(command string) *exec.Cmd {
	if runtime.GOOS == "windows" {
		return exec.Command("cmd", "/C", command)
	}
	return exec.Command("sh", "-c", command)
}

func runCommands(cmds []string) []CommandResult {
	results := make([]CommandResult, 0, len(cmds))
	for _, c := range cmds {
		cmd := buildShellCommand(c)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		start := time.Now()
		err := cmd.Run()
		end := time.Now()
		exitCode := 0
		if cmd.ProcessState != nil {
			exitCode = cmd.ProcessState.ExitCode()
		} else if err != nil {
			exitCode = 1
		}
		results = append(results, CommandResult{
			Command:   c,
			StartTime: start,
			EndTime:   end,
			Duration:  end.Sub(start),
			ExitCode:  exitCode,
			Stdout:    stdout.String(),
			Stderr:    stderr.String(),
		})
	}
	return results
}

func printDryRunOutput(entry *FileEntry, w *strings.Builder) {
	if !entry.IsDir {
		w.WriteString(fmt.Sprintf("%s\n", entry.Path))
		return
	}
	for _, child := range entry.Children {
		printDryRunOutput(child, w)
	}
}

func guessMimeType(path string, content []byte) string {
	if mimeType := mime.TypeByExtension(filepath.Ext(path)); mimeType != "" {
		return mimeType
	}
	if content == nil {
		return "application/octet-stream"
	}
	return http.DetectContentType(content)
}

var rootCmd = &cobra.Command{
	Use:   "flatten [directories]...",
	Short: "Flatten outputs one or more directories as a flat representation",
	Long: `Flatten takes one or more directories as input and outputs
a flat representation of all their contents to stdout. It recursively processes
subdirectories and their contents for each provided directory.`,
	Version: version,
	Args:    cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			args = []string{"."}
		}

		// Validate markdown delimiter
		if markdownDelimiter != "auto" {
			validDelimiter := false
			for _, delimiter := range availableDelimiters {
				if markdownDelimiter == delimiter {
					validDelimiter = true
					break
				}
			}
			if !validDelimiter {
				return fmt.Errorf("invalid markdown delimiter %q, must be one of: auto, %s", markdownDelimiter, strings.Join(availableDelimiters, ", "))
			}
		}

		var tokenizer *tiktoken.Tiktoken
		if showTokens && !dryRun {
			var err error
			tokenizer, err = tiktoken.EncodingForModel(tokensModel)
			if err != nil {
				return fmt.Errorf("failed to get tokenizer for model %q: %w", tokensModel, err)
			}
		}

		var output strings.Builder

		// Create a root entry that will contain all directories
		root := &FileEntry{
			Path:     ".",
			IsDir:    true,
			Children: make([]*FileEntry, 0),
		}

		// Process each directory and add it to the root
		for _, dir := range args {
			filter, err := NewFilter(dir, includeGitIgnore, includeGit, includeBin, includeLocks, includePatterns, excludePatterns)
			if err != nil {
				return fmt.Errorf("failed to create filter for %s: %w", dir, err)
			}

			var dirEntry *FileEntry
			if dryRun {
				dirEntry, err = loadDirectoryDryRun(dir, filter)
			} else {
				dirEntry, err = loadDirectory(dir, filter, tokenizer)
			}
			if err != nil {
				return fmt.Errorf("failed to load directory structure for %s: %w", dir, err)
			}
			if dirEntry == nil {
				continue
			}
			root.Children = append(root.Children, dirEntry)
		}

		if dryRun {
			// Dry-run mode: just list the files that would be included
			output.WriteString(fmt.Sprintf("Files that would be included in flatten output:\n\n"))
			output.WriteString(fmt.Sprintf("Total files: %d\n", getTotalFiles(root)))
			if showTotalSize {
				output.WriteString(fmt.Sprintf("Total size: %d bytes\n", getTotalSize(root)))
			}
			output.WriteString(fmt.Sprintf("\nDirectory structure:\n%s\n", renderDirTree(root, "", false, false)))
			output.WriteString("Files:\n")
			printDryRunOutput(root, &output)
			fmt.Print(output.String())
			return nil
		}

		if showTokens {
			sumTokens(root)
		}

		// Write a single map for all directories
		output.WriteString(fmt.Sprintf("\nTotal files: %d\n", getTotalFiles(root)))
		if showTotalSize {
			output.WriteString(fmt.Sprintf("Total size: %d bytes\n", getTotalSize(root)))
		}
		output.WriteString(fmt.Sprintf("Directory structure:\n%s\n", renderDirTree(root, "", false, showTokens)))

		// Determine the markdown delimiter
		delimiter := markdownDelimiter
		if delimiter == "auto" {
			delimiter = detectBestDelimiter(root)
		}

		fileHashes := make(map[string]*FileHash)
		printFlattenedOutput(root, &output, fileHashes, showTokens, delimiter)

		// If commands were requested, run them and append a detailed report
		if len(commands) > 0 {
			output.WriteString("\nCommands execution:\n")
			results := runCommands(commands)
			for _, r := range results {
				output.WriteString(fmt.Sprintf("\n- command: %s\n", r.Command))
				output.WriteString(fmt.Sprintf("- started: %s\n", r.StartTime.Format(time.RFC3339Nano)))
				output.WriteString(fmt.Sprintf("- finished: %s\n", r.EndTime.Format(time.RFC3339Nano)))
				output.WriteString(fmt.Sprintf("- duration: %s\n", r.Duration))
				output.WriteString(fmt.Sprintf("- exit-code: %d\n", r.ExitCode))
				if r.Stdout != "" {
					output.WriteString(fmt.Sprintf("- stdout:\n%s\n%s\n%s\n", delimiter, r.Stdout, delimiter))
				} else {
					output.WriteString("- stdout: (empty)\n")
				}
				if r.Stderr != "" {
					output.WriteString(fmt.Sprintf("- stderr:\n%s\n%s\n%s\n", delimiter, r.Stderr, delimiter))
				} else {
					output.WriteString("- stderr: (empty)\n")
				}
			}
		}

		fmt.Print(output.String())
		return nil
	},
}

func init() {
	rootCmd.Flags().BoolVarP(&includeGitIgnore, "include-gitignore", "i", false, "Include files normally ignored by .gitignore")
	rootCmd.Flags().BoolVarP(&includeGit, "include-git", "g", false, "Include .git directory")
	rootCmd.Flags().BoolVar(&includeBin, "include-bin", false, "Include binary files in the output")
	rootCmd.Flags().BoolVar(&includeLocks, "include-locks", false, "Include lock files (package-lock.json, yarn.lock, etc.)")
	rootCmd.Flags().BoolVar(&noFileDeduplication, "no-dedup", false, "Disable file deduplication")

	rootCmd.Flags().BoolVarP(&showLastUpdated, "last-updated", "l", false, "Show last updated time for each file")
	rootCmd.Flags().BoolVarP(&showFileMode, "show-mode", "m", false, "Show file permissions")
	rootCmd.Flags().BoolVarP(&showFileSize, "show-size", "z", false, "Show individual file sizes")
	rootCmd.Flags().BoolVarP(&showMimeType, "show-mime", "M", false, "Show file MIME types")
	rootCmd.Flags().BoolVarP(&showSymlinks, "show-symlinks", "y", false, "Show symlink targets")
	rootCmd.Flags().BoolVarP(&showOwnership, "show-owner", "o", false, "Show file owner and group")
	rootCmd.Flags().BoolVarP(&showChecksum, "show-checksum", "c", false, "Show SHA256 checksum of files")
	rootCmd.Flags().BoolVarP(&showAllMetadata, "all-metadata", "a", false, "Show all metadata")
	rootCmd.Flags().BoolVarP(&showTotalSize, "show-total-size", "Z", false, "Show total size of all files")

	rootCmd.Flags().BoolVarP(&showTokens, "tokens", "t", false, "Show token usage for each file/directory")
	rootCmd.Flags().StringVar(&tokensModel, "tokens-model", "gpt-4o-mini", "Model to use for token counting")

	rootCmd.Flags().StringSliceVarP(&includePatterns, "include", "I", []string{}, "Include only files matching these patterns (e.g. '*.go,*.js')")
	rootCmd.Flags().StringSliceVarP(&excludePatterns, "exclude", "E", []string{}, "Exclude files matching these patterns (e.g. '*.test.js')")

	rootCmd.Flags().StringVar(&markdownDelimiter, "markdown-delimiter", "auto", "Markdown code block delimiter (auto, ```, ~~~, `````, ~~~~~, ~~~~~~~~~~~)")
	rootCmd.Flags().BoolVarP(&dryRun, "dry-run", "d", false, "List all files that would be included without processing content")

	// Allow specifying any number of commands. Each --command is executed after flattening.
	rootCmd.Flags().StringArrayVar(&commands, "command", []string{}, "Command to run after flattening (can be repeated)")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
