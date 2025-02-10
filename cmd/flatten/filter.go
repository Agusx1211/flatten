package main

import (
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
	excludedDirs    []string
}

// NewFilter creates a new filter for the given directory.
// Exclude patterns ending with "/" are treated as directory excludes; otherwise, file excludes.
func NewFilter(
	dir string,
	includeGitIgnore bool,
	includeGit bool,
	includeBin bool,
	includePatterns []string,
	excludePatterns []string,
) (*Filter, error) {
	var excludedDirs []string
	var fileExcludePatterns []string

	for _, pat := range excludePatterns {
		if strings.HasSuffix(pat, "/") {
			cleaned := strings.TrimSuffix(pat, "/")
			excludedDirs = append(excludedDirs, cleaned)
		} else {
			fileExcludePatterns = append(fileExcludePatterns, pat)
		}
	}

	f := &Filter{
		includeAll:      includeGitIgnore,
		includeGit:      includeGit,
		includeBin:      includeBin,
		baseDir:         dir,
		includePatterns: includePatterns,
		excludePatterns: fileExcludePatterns,
		excludedDirs:    excludedDirs,
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
	// If not includeAll (--include-gitignore), check gitignore first
	if !f.includeAll && f.gitIgnore != nil {
		relPath, err := filepath.Rel(f.baseDir, path)
		if err == nil {
			relPath = filepath.ToSlash(relPath)
			if f.gitIgnore.MatchesPath(relPath) {
				return false
			}
		}
	}

	// Check excluded directories
	if info.IsDir() && f.isExcludedDir(path) {
		return false
	}

	// Check .git directory exclusion
	if !f.includeGit {
		base := filepath.Base(path)
		if base == ".git" || strings.Contains(filepath.ToSlash(path), "/.git/") {
			return false
		}
	}

	if !info.IsDir() {
		// Check binary exclusion
		if !f.includeBin {
			isBinary, err := f.isBinaryFile(path)
			if err == nil && isBinary {
				return false
			}
		}

		// Check explicit exclude patterns
		if f.matchesAnyPattern(path, f.excludePatterns) {
			return false
		}

		// If include patterns exist, file must match at least one
		if len(f.includePatterns) > 0 {
			return f.matchesAnyPattern(path, f.includePatterns)
		}
	}

	return true
}

func (f *Filter) isExcludedDir(path string) bool {
	rel, err := filepath.Rel(f.baseDir, path)
	if err != nil {
		return false
	}
	rel = filepath.ToSlash(rel)

	for _, dir := range f.excludedDirs {
		if rel == dir || strings.HasPrefix(rel, dir+"/") {
			return true
		}
	}
	return false
}

// isBinaryFile attempts a quick detection of whether the file is binary or text
func (f *Filter) isBinaryFile(path string) (bool, error) {
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

	mimeType := mime.TypeByExtension(filepath.Ext(path))
	if strings.Contains(mimeType, "application/") &&
		!strings.Contains(mimeType, "json") &&
		!strings.Contains(mimeType, "xml") {
		return true, nil
	}

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
