package main

import (
	"os"
	"path/filepath"
	"strings"

	ignore "github.com/sabhiram/go-gitignore"
)

// Filter handles file filtering logic
type Filter struct {
	gitIgnore  *ignore.GitIgnore
	includeAll bool
	includeGit bool
	baseDir    string
}

// NewFilter creates a new filter for the given directory
func NewFilter(dir string, includeGitIgnore bool, includeGit bool) (*Filter, error) {
	f := &Filter{
		includeAll: includeGitIgnore,
		includeGit: includeGit,
		baseDir:    dir,
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
func (f *Filter) ShouldInclude(path string) bool {
	// Check for .git directory unless explicitly included
	if !f.includeGit {
		base := filepath.Base(path)
		if base == ".git" {
			return false
		}
		// Also check if path contains /.git/ to catch subdirectories
		if strings.Contains(filepath.ToSlash(path), "/.git/") {
			return false
		}
	}

	if f.includeAll {
		return true
	}

	// If no .gitignore was found, include everything
	if f.gitIgnore == nil {
		return true
	}

	// Make path relative to the base directory for gitignore matching
	relPath, err := filepath.Rel(f.baseDir, path)
	if err != nil {
		// If we can't get relative path, include the file to be safe
		return true
	}

	// Convert Windows paths to forward slashes for gitignore matching
	relPath = filepath.ToSlash(relPath)

	return !f.gitIgnore.MatchesPath(relPath)
}
