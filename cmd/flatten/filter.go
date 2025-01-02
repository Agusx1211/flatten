package main

import (
	"bufio"
	"fmt"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	ignore "github.com/sabhiram/go-gitignore"
)

// Filter handles file filtering logic
type Filter struct {
	gitIgnore       *ignore.GitIgnore
	includeAll      bool
	includeGit      bool
	includeBin      bool
	baseDir         string
	includePatterns []string
	excludePatterns []string
}

// NewFilter creates a new filter for the given directory
func NewFilter(dir string, includeGitIgnore bool, includeGit bool, includeBin bool, includePatterns []string, excludePatterns []string) (*Filter, error) {
	f := &Filter{
		includeAll:      includeGitIgnore,
		includeGit:      includeGit,
		includeBin:      includeBin,
		baseDir:         dir,
		includePatterns: includePatterns,
		excludePatterns: excludePatterns,
	}

	if !includeGitIgnore {
		gitIgnorePath := filepath.Join(dir, ".gitignore")
		if _, err := os.Stat(gitIgnorePath); err == nil {
			gitIgnore, err := ignore.CompileIgnoreFile(gitIgnorePath)
			if err != nil {
				return nil, err
			}
			f.gitIgnore = gitIgnore
		}
	}

	return f, nil
}

// ShouldInclude returns true if the file/directory should be included
func (f *Filter) ShouldInclude(info os.FileInfo, path string) bool {
	// Matches is applied to the file name, not the path
	if !info.IsDir() {
		// First check include patterns if they exist
		if len(f.includePatterns) > 0 {
			if !f.matchesAnyPattern(path, f.includePatterns) {
				return false
			}
		}

		// Then check exclude patterns
		if f.matchesAnyPattern(path, f.excludePatterns) {
			return false
		}
	}

	// First check git directory rules
	if !f.includeGit {
		base := filepath.Base(path)
		if base == ".git" {
			return false
		}
		if strings.Contains(filepath.ToSlash(path), "/.git/") {
			return false
		}
	}

	// Check if it's a binary file
	if !f.includeBin {
		if !info.IsDir() {
			isBinary, err := f.isBinaryFile(path)
			if err == nil && isBinary {
				return false
			}
		}
	}

	if f.includeAll {
		return true
	}

	// Check gitignore rules
	if f.gitIgnore == nil {
		return true
	}

	relPath, err := filepath.Rel(f.baseDir, path)
	if err != nil {
		return true
	}

	relPath = filepath.ToSlash(relPath)
	return !f.gitIgnore.MatchesPath(relPath)
}

func (f *Filter) addToGitIgnore(filename string) error {
	gitIgnorePath := filepath.Join(f.baseDir, ".gitignore")

	// Check if .gitignore exists
	if _, err := os.Stat(gitIgnorePath); os.IsNotExist(err) {
		// Create new .gitignore with the entry
		content := fmt.Sprintf("# Output files from flatten tool\n%s\n", filename)
		return os.WriteFile(gitIgnorePath, []byte(content), 0644)
	}

	// Check if the entry already exists
	exists, err := f.checkGitIgnoreEntry(filename)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	// Append to existing .gitignore
	file, err := os.OpenFile(gitIgnorePath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = fmt.Fprintf(file, "\n# Output file from flatten tool\n%s\n", filename)
	return err
}

func (f *Filter) checkGitIgnoreEntry(filename string) (bool, error) {
	gitIgnorePath := filepath.Join(f.baseDir, ".gitignore")

	file, err := os.Open(gitIgnorePath)
	if err != nil {
		return false, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == filename {
			return true, nil
		}
	}

	return false, scanner.Err()
}

// Add this helper function to detect binary files
func (f *Filter) isBinaryFile(path string) (bool, error) {
	// Read first 2048 bytes to determine if file is binary
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()

	buffer := make([]byte, 2048)
	n, err := file.Read(buffer)
	if err != nil {
		return false, err
	}
	buffer = buffer[:n]

	// Use mime.TypeByExtension first for known binary formats
	mimeType := mime.TypeByExtension(filepath.Ext(path))
	if strings.Contains(mimeType, "application/") && !strings.Contains(mimeType, "json") && !strings.Contains(mimeType, "xml") {
		return true, nil
	}

	// Use http.DetectContentType as fallback
	contentType := http.DetectContentType(buffer)
	return !strings.HasPrefix(contentType, "text/"), nil
}

func (f *Filter) matchesAnyPattern(path string, patterns []string) bool {
	if len(patterns) == 0 {
		return false
	}

	for _, pattern := range patterns {
		matched, err := filepath.Match(pattern, filepath.Base(path))
		if err == nil && matched {
			return true
		}
	}
	return false
}
