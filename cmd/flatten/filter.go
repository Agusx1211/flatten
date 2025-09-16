package main

import (
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	doublestar "github.com/bmatcuk/doublestar/v4"
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
	includePatterns []globPattern
	excludePatterns []globPattern
}

type globPattern struct {
	pattern string
	dirOnly bool
}

// NewFilter creates a new filter for the given directory.
// Patterns support glob matching. Trailing slashes restrict a pattern to directories only.
func NewFilter(
	dir string,
	includeGitIgnore bool,
	includeGit bool,
	includeBin bool,
	includeLocks bool,
	includePatterns []string,
	excludePatterns []string,
) (*Filter, error) {
	compiledIncludes := compilePatterns(includePatterns)
	compiledExcludes := compilePatterns(excludePatterns)

	f := &Filter{
		includeAll:      includeGitIgnore,
		includeGit:      includeGit,
		includeBin:      includeBin,
		includeLocks:    includeLocks,
		baseDir:         dir,
		includePatterns: compiledIncludes,
		excludePatterns: compiledExcludes,
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
	relPath := f.relativePath(path)
	isDir := info.IsDir()

	if f.matchesPatterns(relPath, isDir, f.excludePatterns) {
		return false
	}

	if !isDir {
		if len(f.includePatterns) > 0 {
			if !f.matchesPatterns(relPath, false, f.includePatterns) {
				return false
			}
		}
	}

	if !f.includeGit {
		relSlash := filepath.ToSlash(relPath)
		base := filepath.Base(path)
		if base == ".git" || relSlash == ".git" || strings.Contains(relSlash, "/.git/") {
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

	if relPath == "." {
		return true
	}

	return !f.gitIgnore.MatchesPath(relPath)
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

func (f *Filter) matchesPatterns(relPath string, isDir bool, patterns []globPattern) bool {
	if len(patterns) == 0 {
		return false
	}

	normalized := strings.ReplaceAll(relPath, "\\", "/")
	base := path.Base(normalized)
	if base == "." && normalized != "." {
		// path.Base returns "." for trailing slash; fallback to last segment manually
		if idx := strings.LastIndex(normalized, "/"); idx >= 0 && idx < len(normalized)-1 {
			base = normalized[idx+1:]
		}
	}

	for _, pattern := range patterns {
		if pattern.pattern == "" {
			if pattern.dirOnly {
				if isDir {
					return true
				}
				continue
			}
			if normalized == "" || normalized == "." {
				return true
			}
		}
		if pattern.dirOnly && !isDir {
			continue
		}
		if matchGlob(pattern.pattern, normalized) {
			return true
		}
		if base != normalized && matchGlob(pattern.pattern, base) {
			return true
		}
	}
	return false
}

func (f *Filter) relativePath(path string) string {
	rel, err := filepath.Rel(f.baseDir, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	if rel == "." {
		return "."
	}
	return filepath.ToSlash(rel)
}

func matchGlob(pattern, target string) bool {
	matched, err := doublestar.PathMatch(pattern, target)
	return err == nil && matched
}

func compilePatterns(patterns []string) []globPattern {
	result := make([]globPattern, 0, len(patterns))
	for _, raw := range patterns {
		pat := normalizePattern(raw)
		if pat.pattern == "" && !pat.dirOnly {
			continue
		}
		result = append(result, pat)
	}
	return result
}

func normalizePattern(raw string) globPattern {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return globPattern{}
	}
	trimmed = strings.ReplaceAll(trimmed, "\\", "/")
	for strings.HasPrefix(trimmed, "./") {
		trimmed = strings.TrimPrefix(trimmed, "./")
	}
	dirOnly := false
	for strings.HasSuffix(trimmed, "/") {
		dirOnly = true
		trimmed = strings.TrimSuffix(trimmed, "/")
	}
	normalized := path.Clean(trimmed)
	if normalized == "." {
		normalized = ""
	}
	normalized = strings.TrimPrefix(normalized, "/")
	return globPattern{pattern: normalized, dirOnly: dirOnly}
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
