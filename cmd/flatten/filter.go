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
	includeLocks    bool
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
	includeLocks bool,
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
		includeLocks:    includeLocks,
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
	if info.IsDir() && f.isExcludedDir(path) {
		return false
	}

	if !info.IsDir() {
		if len(f.includePatterns) > 0 {
			if !f.matchesAnyPattern(path, f.includePatterns) {
				return false
			}
		}
		if f.matchesAnyPattern(path, f.excludePatterns) {
			return false
		}
	}

	if !f.includeGit {
		base := filepath.Base(path)
		if base == ".git" || strings.Contains(filepath.ToSlash(path), "/.git/") {
			return false
		}
	}

	if !f.includeLocks && !info.IsDir() {
		base := filepath.Base(path)
		if isLockFile(base) {
			return false
		}
	}

	if !f.includeBin && !info.IsDir() {
		isBinary, err := f.isBinaryFile(path)
		if err == nil && isBinary {
			return false
		}
	}

	if f.includeAll {
		return true
	}

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

func (f *Filter) isBinaryFile(path string) (bool, error) {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case
		".txt", ".md", ".markdown", ".rst", ".org",
		".html", ".htm", ".xhtml", ".xml",
		".css", ".scss", ".sass", ".less",
		".js", ".cjs", ".mjs", ".jsx",
		".ts", ".tsx",
		".c", ".cpp", ".h", ".hpp", ".cc", ".cxx", ".hh",
		".go", ".py", ".pyi", ".pyw", ".rb", ".php", ".phtml", ".java", ".cs", ".vb",
		".sh", ".bash", ".zsh", ".fish", ".bat", ".ps1",
		".sql", ".graphql", ".gql",
		".json", ".json5", ".yaml", ".yml", ".toml", ".ini", ".env", ".cfg", ".conf",
		".lua", ".rs", ".swift", ".scala", ".dart", ".erl", ".elixir",
		".svg", ".vue", ".svelte",
		".lock", ".gitignore", ".gitattributes", ".dockerignore", ".editorconfig",
		".eslint", ".eslintrc", ".prettierrc", ".babelrc", ".stylelintrc",
		".npmrc", ".yarnrc":
		// Treat all these known text-based extensions as non-binary
		return false, nil
	}

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

	mimeType := mime.TypeByExtension(ext)
	// If it's "application/" but not explicitly JSON/XML, treat as binary
	if strings.Contains(mimeType, "application/") &&
		!strings.Contains(mimeType, "json") &&
		!strings.Contains(mimeType, "xml") {
		return true, nil
	}

	// Fallback to sniffing the first bytes
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

// isLockFile checks if a file is a lock file
func isLockFile(filename string) bool {
	lockFiles := []string{
		"package-lock.json",
		"yarn.lock",
		"pnpm-lock.yaml",
		"Pipfile.lock",
		"poetry.lock",
		"Gemfile.lock",
		"go.sum",
		"Cargo.lock",
		"composer.lock",
		"mix.lock",
		"shard.lock",
		"flake.lock",
		"gradle.lockfile",
		"packages.lock.json",
		"project.lock.json",
	}

	for _, lockFile := range lockFiles {
		if strings.EqualFold(filename, lockFile) {
			return true
		}
	}

	return strings.HasSuffix(filename, ".lock")
}
