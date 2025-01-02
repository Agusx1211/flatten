package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

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

var includeGitIgnore bool
var includeGit bool
var toFile bool
var fileName string
var skipGitIgnoreAdd bool

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

// printFlattenedOutput prints all files and their contents
func printFlattenedOutput(entry *FileEntry, w *strings.Builder) {
	if !entry.IsDir {
		w.WriteString(fmt.Sprintf("\n- path: %s\n", entry.Path))
		w.WriteString(fmt.Sprintf("- content:\n```\n%s\n```\n", string(entry.Content)))
		return
	}

	for _, child := range entry.Children {
		printFlattenedOutput(child, w)
	}
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
		filter, err := NewFilter(dir, includeGitIgnore, includeGit)
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

		// Write flattened file contents
		printFlattenedOutput(root, &output)

		// Handle output based on flags
		if toFile {
			err := os.WriteFile(fileName, []byte(output.String()), 0644)
			if err != nil {
				return fmt.Errorf("failed to write to file: %w", err)
			}
			fmt.Printf("Output written to: %s\n", fileName)

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
	rootCmd.Flags().BoolVar(&includeGitIgnore, "include-gitignore", false, "Include files that would normally be ignored by .gitignore")
	rootCmd.Flags().BoolVar(&includeGit, "include-git", false, "Include .git directory and its contents")
	rootCmd.Flags().BoolVar(&toFile, "tf", false, "Write output to file instead of stdout")
	rootCmd.Flags().StringVar(&fileName, "fn", "./flat", "Output file name (only used with --tf)")
	rootCmd.Flags().BoolVar(&skipGitIgnoreAdd, "skip-gitignore", false, "Skip adding output file to .gitignore")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
