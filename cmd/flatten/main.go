package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/pkoukk/tiktoken-go"
	"github.com/spf13/cobra"
)

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

	showTokens  bool
	tokensModel string

	includePatterns []string
	excludePatterns []string
)

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
		name := filepath.Base(entry.Path)
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
	hasher := sha256.New()
	hasher.Write(content)
	return hex.EncodeToString(hasher.Sum(nil))
}

func printFlattenedOutput(entry *FileEntry, w *strings.Builder, fileHashes map[string]*FileHash, showTokens bool) {
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
			info, err := os.Stat(entry.Path)
			if err == nil {
				if stat, ok := info.Sys().(*syscall.Stat_t); ok {
					if owner, err := user.LookupId(fmt.Sprint(stat.Uid)); err == nil {
						w.WriteString(fmt.Sprintf("- owner: %s\n", owner.Username))
					}
					if group, err := user.LookupGroupId(fmt.Sprint(stat.Gid)); err == nil {
						w.WriteString(fmt.Sprintf("- group: %s\n", group.Name))
					}
				}
			}
		}
		if showAllMetadata || showChecksum {
			hash := calculateFileHash(entry.Content)
			w.WriteString(fmt.Sprintf("- sha256: %s\n", hash))
		}
		if showTokens {
			w.WriteString(fmt.Sprintf("- tokens: %d\n", entry.Tokens))
		}
		if noFileDeduplication {
			w.WriteString(fmt.Sprintf("- content:\n```\n%s\n```\n", string(entry.Content)))
			return
		}
		hash := calculateFileHash(entry.Content)
		if existing, exists := fileHashes[hash]; exists {
			w.WriteString(fmt.Sprintf("- content: Contents are identical to %s\n", existing.Path))
		} else {
			fileHashes[hash] = &FileHash{Path: entry.Path, Hash: hash, Content: entry.Content}
			w.WriteString(fmt.Sprintf("- content:\n```\n%s\n```\n", string(entry.Content)))
		}
		return
	}
	if showTokens {
		w.WriteString(fmt.Sprintf("\n- path: %s\n", entry.Path))
		w.WriteString(fmt.Sprintf("- dir tokens: %d\n", entry.Tokens))
	}
	for _, child := range entry.Children {
		printFlattenedOutput(child, w, fileHashes, showTokens)
	}
}

func guessMimeType(path string, content []byte) string {
	if mimeType := mime.TypeByExtension(filepath.Ext(path)); mimeType != "" {
		return mimeType
	}
	return http.DetectContentType(content)
}

var rootCmd = &cobra.Command{
	Use:   "flatten [directories]...",
	Short: "Flatten outputs one or more directories as a flat representation",
	Long: `Flatten takes one or more directories as input and outputs
a flat representation of all their contents to stdout. It recursively processes
subdirectories and their contents for each provided directory.`,
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			args = []string{"."}
		}

		var tokenizer *tiktoken.Tiktoken
		if showTokens {
			var err error
			tokenizer, err = tiktoken.EncodingForModel(tokensModel)
			if err != nil {
				return fmt.Errorf("failed to get tokenizer for model %q: %w", tokensModel, err)
			}
		}

		fileHashes := make(map[string]*FileHash)
		var output strings.Builder

		for _, dir := range args {
			filter, err := NewFilter(dir, includeGitIgnore, includeGit, includeBin, includeLocks, includePatterns, excludePatterns)
			if err != nil {
				return fmt.Errorf("failed to create filter for %s: %w", dir, err)
			}
			root, err := loadDirectory(dir, filter, tokenizer)
			if err != nil {
				return fmt.Errorf("failed to load directory structure for %s: %w", dir, err)
			}
			if root == nil {
				continue
			}
			if showTokens {
				sumTokens(root)
			}
			output.WriteString(fmt.Sprintf("\nDirectory: %s\n", dir))
			output.WriteString(fmt.Sprintf("- Total files: %d\n", getTotalFiles(root)))
			output.WriteString(fmt.Sprintf("- Total size: %d bytes\n", getTotalSize(root)))
			output.WriteString(fmt.Sprintf("- Dir tree:\n%s\n", renderDirTree(root, "", false, showTokens)))
			printFlattenedOutput(root, &output, fileHashes, showTokens)
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

	rootCmd.Flags().BoolVarP(&showTokens, "tokens", "t", false, "Show token usage for each file/directory")
	rootCmd.Flags().StringVar(&tokensModel, "tokens-model", "gpt-4o-mini", "Model to use for token counting")

	rootCmd.Flags().StringSliceVarP(&includePatterns, "include", "I", []string{}, "Include only files matching these patterns (e.g. '*.go,*.js')")
	rootCmd.Flags().StringSliceVarP(&excludePatterns, "exclude", "E", []string{}, "Exclude files matching these patterns (e.g. '*.test.js')")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
