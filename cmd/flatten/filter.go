package main

import (
	"fmt"
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
	gitIgnore          *ignore.GitIgnore
	gitIgnoreLines     []string
	includeAll         bool
	includeGit         bool
	includeBin         bool
	includeLocks       bool
	baseDir            string
	includePatterns    []globPattern
	excludePatterns    []globPattern
	profile            string
	hasDirOnlyIncludes bool
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
	profile string,
) (*Filter, error) {
	compiledIncludes := compilePatterns(includePatterns)
	compiledExcludes := compilePatterns(excludePatterns)

	f := &Filter{
		includeAll:         includeGitIgnore,
		includeGit:         includeGit,
		includeBin:         includeBin,
		includeLocks:       includeLocks,
		baseDir:            dir,
		includePatterns:    compiledIncludes,
		excludePatterns:    compiledExcludes,
		profile:            profile,
		hasDirOnlyIncludes: hasDirOnlyPattern(compiledIncludes),
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

	if isDir && f.hasDirOnlyIncludes && len(f.includePatterns) > 0 {
		if !f.matchesPatterns(relPath, true, f.includePatterns) {
			return false
		}
	}

	if !isDir && len(f.includePatterns) > 0 {
		if !f.matchesPatterns(relPath, false, f.includePatterns) {
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

// WithGitIgnoreFile returns a new Filter that includes rules from a .gitignore file found in dir.
// If no .gitignore file is present, the current filter is returned unchanged.
func (f *Filter) WithGitIgnoreFile(dir string) (*Filter, error) {
	if f.includeAll {
		return f, nil
	}

	gitIgnorePath := filepath.Join(dir, ".gitignore")
	info, err := os.Stat(gitIgnorePath)
	if err != nil {
		if os.IsNotExist(err) {
			return f, nil
		}
		return nil, fmt.Errorf("failed to stat %s: %w", gitIgnorePath, err)
	}
	if info.IsDir() {
		return f, nil
	}

	content, err := os.ReadFile(gitIgnorePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", gitIgnorePath, err)
	}

	lines := strings.Split(string(content), "\n")
	relDir := f.relativePath(dir)
	prefixed := prefixGitIgnoreLines(lines, relDir)

	newLines := append([]string{}, f.gitIgnoreLines...)
	newLines = append(newLines, prefixed...)

	gi := ignore.CompileIgnoreLines(newLines...)

	nf := *f
	nf.gitIgnoreLines = newLines
	nf.gitIgnore = gi
	return &nf, nil
}

func prefixGitIgnoreLines(lines []string, relDir string) []string {
	if relDir == "" || relDir == "." {
		return lines
	}

	relDir = strings.TrimPrefix(relDir, "./")
	relDir = strings.TrimPrefix(relDir, "/")
	relDir = strings.TrimSuffix(relDir, "/")
	if relDir == "" || relDir == "." {
		return lines
	}

	prefix := path.Clean(relDir)
	if prefix == "." || prefix == "/" {
		return lines
	}

	out := make([]string, 0, len(lines))
	for _, raw := range lines {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			out = append(out, raw)
			continue
		}

		negated := strings.HasPrefix(trimmed, "!")
		pat := trimmed
		if negated {
			pat = strings.TrimPrefix(pat, "!")
		}

		anchored := strings.HasPrefix(pat, "/")
		pat = strings.TrimPrefix(pat, "/")

		dirOnly := strings.HasSuffix(pat, "/")
		patTrim := strings.TrimSuffix(pat, "/")
		patTrim = strings.TrimPrefix(patTrim, "./")
		patTrim = strings.TrimPrefix(patTrim, "/")

		hasSlashInBody := strings.Contains(patTrim, "/")

		var joined string
		switch {
		case anchored:
			// anchored to the directory that owns the .gitignore
			joined = path.Join(prefix, patTrim)
		case hasSlashInBody:
			// relative to the directory that owns the .gitignore
			joined = path.Join(prefix, patTrim)
		default:
			// no "/" patterns match at any depth under the .gitignore directory
			joined = path.Join(prefix, "**", patTrim)
		}

		if dirOnly {
			joined += "/"
		}

		// Use a leading slash to scope nested rules to this subtree.
		prefixedLine := "/" + joined
		if negated {
			prefixedLine = "!" + prefixedLine
		}

		out = append(out, prefixedLine)
	}

	return out
}

// WithFlattenFile returns a new Filter that includes the rules defined in a .flatten file found in dir.
// If no .flatten file is present, the current filter is returned unchanged.
func (f *Filter) WithFlattenFile(dir string) (*Filter, error) {
	flattenPath := filepath.Join(dir, flattenFileName)
	info, err := os.Stat(flattenPath)
	if err != nil {
		if os.IsNotExist(err) {
			return f, nil
		}
		return nil, fmt.Errorf("failed to stat %s: %w", flattenPath, err)
	}
	if info.IsDir() {
		return f, nil
	}

	rules, err := readFlattenFile(flattenPath, f.profile)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", flattenPath, err)
	}

	if rules == nil || (len(rules.include) == 0 && len(rules.exclude) == 0) {
		return f, nil
	}

	relDir := f.relativePath(dir)
	prefixedIncludes := prefixPatternsWithDir(rules.include, relDir)
	prefixedExcludes := prefixPatternsWithDir(rules.exclude, relDir)

	newIncludes := append(copyGlobPatterns(f.includePatterns), compilePatterns(prefixedIncludes)...)
	newExcludes := append(copyGlobPatterns(f.excludePatterns), compilePatterns(prefixedExcludes)...)

	nf := *f
	nf.includePatterns = newIncludes
	nf.excludePatterns = newExcludes
	nf.hasDirOnlyIncludes = hasDirOnlyPattern(newIncludes)
	return &nf, nil
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

func hasDirOnlyPattern(patterns []globPattern) bool {
	for _, pat := range patterns {
		if pat.dirOnly {
			return true
		}
	}
	return false
}

func copyGlobPatterns(in []globPattern) []globPattern {
	if len(in) == 0 {
		return nil
	}
	out := make([]globPattern, len(in))
	copy(out, in)
	return out
}

func prefixPatternsWithDir(patterns []string, dir string) []string {
	if len(patterns) == 0 {
		return patterns
	}

	cleanDir := strings.TrimSpace(dir)
	cleanDir = strings.TrimPrefix(cleanDir, "./")
	cleanDir = strings.TrimPrefix(cleanDir, "/")
	cleanDir = strings.TrimSuffix(cleanDir, "/")
	if cleanDir == "" || cleanDir == "." {
		return patterns
	}

	result := make([]string, 0, len(patterns))
	for _, raw := range patterns {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			result = append(result, trimmed)
			continue
		}
		hasTrailingSlash := strings.HasSuffix(trimmed, "/")
		normalized := strings.ReplaceAll(trimmed, "\\", "/")
		normalized = strings.TrimPrefix(normalized, "/")
		normalized = strings.TrimSuffix(normalized, "/")
		joined := path.Join(cleanDir, normalized)
		if hasTrailingSlash {
			joined += "/"
		}
		result = append(result, joined)
	}

	return result
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
