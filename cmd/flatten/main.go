package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

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
	Children []*FileEntry
}

// FileHash represents a file hash and its path
type FileHash struct {
	Path    string
	Hash    string
	Content []byte
}

var includeGitIgnore bool
var includeGit bool
var toFile bool
var fileName string
var skipGitIgnoreAdd bool
var autoDelete bool
var autoDeleteTime int
var noFileDeduplication bool
var unsafe bool
var showLastUpdated bool
var showFileMode bool
var showFileSize bool
var showMimeType bool
var showSymlinks bool
var showOwnership bool
var showChecksum bool
var showAllMetadata bool
var includeBin bool

func loadDirectory(path string, filter *Filter) (*FileEntry, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat path %s: %w", path, err)
	}

	// Check if the file should be included
	if !filter.ShouldInclude(path) {
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
		return entry, nil
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory %s: %w", path, err)
	}

	for _, item := range entries {
		childPath := filepath.Join(path, item.Name())
		child, err := loadDirectory(childPath, filter)
		if err != nil {
			return nil, err
		}
		// Only append child if it wasn't filtered out
		if child != nil {
			entry.Children = append(entry.Children, child)
		}
	}

	return entry, nil
}

// getTotalFiles returns the total number of files (excluding directories)
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

// getTotalSize returns the total size of all files
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

// renderDirTree returns a string representation of the directory tree
func renderDirTree(entry *FileEntry, prefix string, isLast bool) string {
	var sb strings.Builder

	if entry.Path != "." {
		marker := "├── "
		if isLast {
			marker = "└── "
		}
		sb.WriteString(prefix + marker + filepath.Base(entry.Path) + "\n")
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
			sb.WriteString(renderDirTree(child, newPrefix, isLastChild))
		}
	}

	return sb.String()
}

// calculateFileHash calculates the SHA256 hash of a file content
func calculateFileHash(content []byte) string {
	hasher := sha256.New()
	hasher.Write(content)
	return hex.EncodeToString(hasher.Sum(nil))
}

// printFlattenedOutput prints all files and their contents
func printFlattenedOutput(entry *FileEntry, w *strings.Builder, fileHashes map[string]*FileHash) {
	if !entry.IsDir {
		// Write basic path info
		w.WriteString(fmt.Sprintf("\n- path: %s\n", entry.Path))

		// Add metadata based on enabled flags or all-metadata flag
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
			mimeType := mime.TypeByExtension(filepath.Ext(entry.Path))
			if mimeType == "" {
				mimeType = http.DetectContentType(entry.Content)
			}
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

		// Handle content output with deduplication logic
		if noFileDeduplication {
			w.WriteString(fmt.Sprintf("- content:\n```\n%s\n```\n", string(entry.Content)))
			return
		}

		hash := calculateFileHash(entry.Content)
		if existing, exists := fileHashes[hash]; exists {
			// This is a duplicate file
			w.WriteString(fmt.Sprintf("- content: Contents are identical to %s\n", existing.Path))
		} else {
			// This is the first occurrence of this file content
			fileHashes[hash] = &FileHash{
				Path:    entry.Path,
				Hash:    hash,
				Content: entry.Content,
			}
			w.WriteString(fmt.Sprintf("- content:\n```\n%s\n```\n", string(entry.Content)))
		}
		return
	}

	// Process directory contents
	for _, child := range entry.Children {
		printFlattenedOutput(child, w, fileHashes)
	}
}

func scheduleFileDelete(filePath string, seconds int) error {
	// Check for existing delete process
	if pid, err := findExistingDeleteProcess(filePath); err != nil {
		return fmt.Errorf("failed to check for existing delete process: %w", err)
	} else if pid != 0 {
		// Found existing process, kill it
		if err := killProcess(pid); err != nil {
			return fmt.Errorf("failed to kill existing delete process: %w", err)
		}
	}

	// Get absolute path for the file
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	// Create a shell script that checks the file before deleting
	script := fmt.Sprintf(`
sleep %d
if [ -f "%s" ]; then
    if head -n 2 "%s" | grep -q "^- Total files: " && head -n 2 "%s" | grep -q "^- Total size: "; then
        rm "%s"
    else
        echo "Warning: File %s no longer appears to be a flattener output. Deletion skipped."
    fi
fi
`, seconds, absPath, absPath, absPath, absPath, absPath)

	// Create the command
	cmd := exec.Command("sh", "-c", script)

	// Detach the process
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	return cmd.Start()
}

func isFlattenerOutput(path string) (bool, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}

	lines := strings.Split(string(content), "\n")
	if len(lines) < 2 {
		return false, nil
	}

	return strings.HasPrefix(lines[0], "- Total files: ") &&
		strings.HasPrefix(lines[1], "- Total size: "), nil
}

// findExistingDeleteProcess looks for a process that matches our delete script pattern
func findExistingDeleteProcess(filePath string) (int, error) {
	// Get absolute path for consistent comparison
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return 0, err
	}

	// Use ps to find sleep processes and their parent sh processes
	cmd := exec.Command("ps", "-ef")
	output, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("failed to list processes: %w", err)
	}

	// Split output into lines
	lines := strings.Split(string(output), "\n")

	// Look for our specific script pattern
	for _, line := range lines {
		if strings.Contains(line, "sleep") &&
			strings.Contains(line, absPath) &&
			strings.Contains(line, "head -n 2") &&
			strings.Contains(line, "rm") &&
			strings.Contains(line, "Total files:") &&
			strings.Contains(line, "Total size:") &&
			strings.Contains(line, "grep -q") {
			// Extract PID - ps output format is: UID PID PPID ...
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			pid, err := strconv.Atoi(fields[1])
			if err != nil {
				continue
			}
			return pid, nil
		}
	}

	return 0, nil
}

// killProcess attempts to kill a process and its children
func killProcess(pid int) error {
	// First try to kill child processes
	cmd := exec.Command("pkill", "-P", strconv.Itoa(pid))
	_ = cmd.Run() // Ignore errors as there might not be any children

	// Then kill the main process
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return process.Kill()
}

var rootCmd = &cobra.Command{
	Use:   "flatten [directory]",
	Short: "Flatten outputs a directory structure as a flat representation",
	Long: `Flatten is a CLI tool that takes a directory as input and outputs
a flat representation of all its contents to stdout. It recursively processes
all subdirectories and their contents.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		dir := "."
		if len(args) > 0 {
			dir = args[0]
		}

		// Create the filter
		filter, err := NewFilter(dir, includeGitIgnore, includeGit, includeBin)
		if err != nil {
			return fmt.Errorf("failed to create filter: %w", err)
		}

		root, err := loadDirectory(dir, filter)
		if err != nil {
			return fmt.Errorf("failed to load directory structure: %w", err)
		}

		// Create a string builder for the output
		var output strings.Builder

		// Write summary and directory tree
		output.WriteString(fmt.Sprintf("- Total files: %d\n", getTotalFiles(root)))
		output.WriteString(fmt.Sprintf("- Total size: %d bytes\n", getTotalSize(root)))
		output.WriteString(fmt.Sprintf("- Dir tree:\n%s\n", renderDirTree(root, "", false)))

		// Initialize fileHashes map
		fileHashes := make(map[string]*FileHash)

		// Write flattened file contents with duplicate detection
		printFlattenedOutput(root, &output, fileHashes)

		// Handle output based on flags
		if toFile {
			// Check if file exists and verify it's safe to overwrite
			if _, err := os.Stat(fileName); err == nil && !unsafe {
				// File exists, check if it's a flattener output
				isFlattenerFile, err := isFlattenerOutput(fileName)
				if err != nil {
					return fmt.Errorf("failed to check existing file: %w", err)
				}
				if !isFlattenerFile {
					return fmt.Errorf("refusing to overwrite %s: file exists and doesn't appear to be flattener output. Use --unsafe to override", fileName)
				}
			}

			err := os.WriteFile(fileName, []byte(output.String()), 0644)
			if err != nil {
				return fmt.Errorf("failed to write to file: %w", err)
			}
			fmt.Printf("Output written to: %s\n", fileName)

			// Add auto-delete if enabled
			if autoDelete {
				if err := scheduleFileDelete(fileName, autoDeleteTime); err != nil {
					return fmt.Errorf("failed to schedule file deletion: %w", err)
				}
				fmt.Printf("File will be automatically deleted after %d seconds\n", autoDeleteTime)
			}

			// Add to .gitignore if appropriate
			if !skipGitIgnoreAdd {
				baseFileName := filepath.Base(fileName)
				if err := filter.addToGitIgnore(baseFileName); err != nil {
					return fmt.Errorf("failed to update .gitignore: %w", err)
				}
			}
		} else {
			fmt.Print(output.String())
		}

		return nil
	},
}

func init() {
	rootCmd.Flags().BoolVarP(&includeGitIgnore, "include-gitignore", "i", false, "Include files that would normally be ignored by .gitignore")
	rootCmd.Flags().BoolVarP(&includeGit, "include-git", "g", false, "Include .git directory and its contents")
	rootCmd.Flags().BoolVarP(&toFile, "to-file", "f", false, "Write output to file instead of stdout")
	rootCmd.Flags().StringVarP(&fileName, "file-name", "n", "./flat", "Output file name (only used with --to-file)")
	rootCmd.Flags().BoolVarP(&skipGitIgnoreAdd, "skip-gitignore", "s", false, "Skip adding output file to .gitignore")
	rootCmd.Flags().BoolVarP(&autoDelete, "auto-delete", "d", false, "Auto delete the output file after N seconds (only used with --to-file)")
	rootCmd.Flags().IntVar(&autoDeleteTime, "auto-delete-time", 30, "Auto delete time in seconds (only used with --auto-delete)")
	rootCmd.Flags().BoolVar(&noFileDeduplication, "no-dedup", false, "Disable file deduplication")
	rootCmd.Flags().BoolVar(&unsafe, "unsafe", false, "Allow overwriting non-flattener output files")
	rootCmd.Flags().BoolVarP(&showLastUpdated, "last-updated", "l", false, "Show last updated time for each file")
	rootCmd.Flags().BoolVarP(&showFileMode, "show-mode", "m", false, "Show file permissions")
	rootCmd.Flags().BoolVarP(&showFileSize, "show-size", "z", false, "Show individual file sizes")
	rootCmd.Flags().BoolVarP(&showMimeType, "show-mime", "t", false, "Show file MIME types")
	rootCmd.Flags().BoolVarP(&showSymlinks, "show-symlinks", "y", false, "Show symlink targets")
	rootCmd.Flags().BoolVarP(&showOwnership, "show-owner", "o", false, "Show file owner and group")
	rootCmd.Flags().BoolVarP(&showChecksum, "show-checksum", "c", false, "Show SHA256 checksum of files")
	rootCmd.Flags().BoolVarP(&showAllMetadata, "all-metadata", "a", false, "Show all available metadata")
	rootCmd.Flags().BoolVar(&includeBin, "include-bin", false, "Include binary files in the output")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
