package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pkoukk/tiktoken-go"
	"github.com/spf13/cobra"
)

// Version information (set by build process)
var version = "dev"

// FileEntry represents a file in the flattened structure
type FileEntry struct {
	Path      string
	IsDir     bool
	Size      int64
	Mode      fs.FileMode
	ModTime   int64
	Content   []byte
	ReadError string
	Tokens    int
	Children  []*FileEntry
}

// FileHash is used for deduplication
type FileHash struct {
	Path    string
	Hash    string
	Content []byte
}

type OutputSection struct {
	Label string
	Start int
	End   int
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

	showLineNumbers bool

	showTokens  bool
	tokensModel string

	tcount         bool
	tcountDetailed bool
	tcountModel    string

	outputPrint      bool
	outputCopy       bool
	outputSSHCopy    bool
	setDefaultOutput bool
	silent           bool

	includePatterns []string
	excludePatterns []string
	profileName     string

	markdownDelimiter string
	dryRun            bool

	// commands to run after flattening
	commands []string

	// Optional surrounding messages
	prefixMessage string
	suffixMessage string

	// Output compression
	compressOutput bool
	compressLevel  int
)

// Available markdown delimiters in order of preference for auto-detection
var availableDelimiters = []string{"```", "~~~", "`````", "~~~~~", "~~~~~~~~~~~"}

func scanTextForDelimiters(content string, usedDelimiters map[string]bool) {
	for _, delimiter := range availableDelimiters {
		if strings.Contains(content, delimiter) {
			usedDelimiters[delimiter] = true
		}
	}
}

// detectBestDelimiter scans all files (and optional command outputs) and returns the first delimiter that's not used
func detectBestDelimiter(root *FileEntry, cmdResults []CommandResult) string {
	usedDelimiters := make(map[string]bool)

	// Recursively scan all files for delimiter usage
	scanForDelimiters(root, usedDelimiters)

	// Also scan command stdout/stderr since those are wrapped in a delimiter too.
	for _, r := range cmdResults {
		if r.Stdout != "" {
			scanTextForDelimiters(r.Stdout, usedDelimiters)
		}
		if r.Stderr != "" {
			scanTextForDelimiters(r.Stderr, usedDelimiters)
		}
	}

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
		scanTextForDelimiters(string(entry.Content), usedDelimiters)
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
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat path %s: %w", path, err)
	}
	if !filter.ShouldInclude(info, path) {
		return nil, nil
	}
	isSymlink := info.Mode()&os.ModeSymlink != 0
	entry := &FileEntry{
		Path:     path,
		IsDir:    info.IsDir(),
		Size:     info.Size(),
		Mode:     info.Mode(),
		ModTime:  info.ModTime().Unix(),
		Children: make([]*FileEntry, 0),
	}
	if isSymlink {
		entry.Content = []byte{}
		target, err := os.Readlink(path)
		if err == nil {
			entry.Content = []byte(target)
			if tokenizer != nil {
				toks := tokenizer.Encode(target, nil, nil)
				entry.Tokens = len(toks)
			}
		}
		return entry, nil
	}
	if !info.IsDir() {
		content, err := os.ReadFile(path)
		if err != nil {
			entry.ReadError = err.Error()
			return entry, nil
		}
		entry.Content = content
		if tokenizer != nil {
			toks := tokenizer.Encode(string(content), nil, nil)
			entry.Tokens = len(toks)
		}
		return entry, nil
	}
	childFilter := filter
	if info.IsDir() {
		updatedFilter, err := filter.WithFlattenFile(path)
		if err != nil {
			return nil, err
		}
		updatedFilter, err = updatedFilter.WithGitIgnoreFile(path)
		if err != nil {
			return nil, err
		}
		childFilter = updatedFilter
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		entry.ReadError = err.Error()
		return entry, nil
	}
	for _, item := range entries {
		childPath := filepath.Join(path, item.Name())
		child, err := loadDirectory(childPath, childFilter, tokenizer)
		if err != nil {
			return nil, err
		}
		if child != nil {
			entry.Children = append(entry.Children, child)
		}
	}
	if len(childFilter.includePatterns) > 0 && len(entry.Children) == 0 {
		return nil, nil
	}
	return entry, nil
}

func loadDirectoryDryRun(path string, filter *Filter) (*FileEntry, error) {
	info, err := os.Lstat(path)
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
	childFilter := filter
	if info.IsDir() {
		updatedFilter, err := filter.WithFlattenFile(path)
		if err != nil {
			return nil, err
		}
		updatedFilter, err = updatedFilter.WithGitIgnoreFile(path)
		if err != nil {
			return nil, err
		}
		childFilter = updatedFilter
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		entry.ReadError = err.Error()
		return entry, nil
	}
	for _, item := range entries {
		childPath := filepath.Join(path, item.Name())
		child, err := loadDirectoryDryRun(childPath, childFilter)
		if err != nil {
			return nil, err
		}
		if child != nil {
			entry.Children = append(entry.Children, child)
		}
	}
	if len(childFilter.includePatterns) > 0 && len(entry.Children) == 0 {
		return nil, nil
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

func renderDirTree(entry *FileEntry, prefix string, isLast bool, showTokens bool, isRoot bool, showFullPath bool) string {
	var sb strings.Builder
	if isRoot {
		name := entry.Path
		if name == "" {
			name = "."
		}
		if entry.ReadError != "" {
			name = fmt.Sprintf("%s (unreadable)", name)
		}
		if showTokens {
			name = fmt.Sprintf("%s (%d tokens)", name, entry.Tokens)
		}
		sb.WriteString(name + "\n")
	} else {
		marker := "├── "
		if isLast {
			marker = "└── "
		}
		name := entry.Path
		if !showFullPath {
			name = filepath.Base(entry.Path)
		}
		if entry.ReadError != "" {
			name = fmt.Sprintf("%s (unreadable)", name)
		}
		if showTokens {
			name = fmt.Sprintf("%s (%d tokens)", name, entry.Tokens)
		}
		sb.WriteString(prefix + marker + name + "\n")
	}
	if entry.IsDir {
		newPrefix := prefix
		if !isRoot {
			if isLast {
				newPrefix += "    "
			} else {
				newPrefix += "│   "
			}
		}
		for i, child := range entry.Children {
			isLastChild := i == len(entry.Children)-1
			sb.WriteString(renderDirTree(child, newPrefix, isLastChild, showTokens, false, false))
		}
	}
	return sb.String()
}

func renderDirTreeForOutput(root *FileEntry, showTokens bool) string {
	if root == nil {
		return ""
	}

	// If we only have a single top-level directory, treat that directory as the tree root.
	if root.IsDir && root.Path == "." && len(root.Children) == 1 && root.Children[0] != nil && root.Children[0].IsDir {
		return renderDirTree(root.Children[0], "", true, showTokens, true, false)
	}

	// Multi-root output: print each top-level entry with its full path.
	if root.IsDir && root.Path == "." {
		var sb strings.Builder
		for i, child := range root.Children {
			isLastChild := i == len(root.Children)-1
			sb.WriteString(renderDirTree(child, "", isLastChild, showTokens, false, true))
		}
		return sb.String()
	}

	return renderDirTree(root, "", true, showTokens, true, false)
}

func calculateFileHash(content []byte) string {
	if content == nil {
		return ""
	}
	hasher := sha256.New()
	hasher.Write(content)
	return hex.EncodeToString(hasher.Sum(nil))
}

// --- Compression helpers ---

// BlobDef represents a large repeated blob extracted out of the content
type BlobDef struct {
	ID      string
	Hash    string
	Content string
	Count   int
}

// CompressionContext carries configuration and runtime state for compression
type CompressionContext struct {
	Level       int
	BlobMinHits int

	// Lossy transforms (progressively more aggressive by level)
	TrimTrailingWhitespace bool
	StripBlankLines        bool
	StripCommentLines      bool

	// Blob extraction
	LargeBlobThresholdBytes int
	HeaderBlobMinBytes      int
	HeaderBlobMaxBytes      int
	HeaderBlobMaxLines      int

	// Repeated-block compression
	MaxRepeatGroupLines int

	// Truncation (level 3+). If either min threshold is exceeded, output is truncated.
	TruncateMinBytes  int
	TruncateMinLines  int
	TruncateHead      int
	TruncateTail      int
	TruncateHeadBytes int
	TruncateTailBytes int

	Enabled     bool
	BlobsByID   map[string]*BlobDef
	BlobsByHash map[string]*BlobDef
	BlobIDs     []string
	UsedBlobIDs map[string]bool
	Applied     bool

	AppliedBlobs      bool
	AppliedRepeats    bool
	AppliedTruncation bool
	AppliedWhitespace bool
	AppliedComments   bool
	AppliedOutline    bool
}

func newCompressionContext(level int) (*CompressionContext, error) {
	if level <= 0 {
		return nil, nil
	}
	if level > 3 {
		return nil, fmt.Errorf("invalid compression level %d (must be 1..3)", level)
	}

	ctx := &CompressionContext{
		Enabled:     true,
		Level:       level,
		UsedBlobIDs: make(map[string]bool),
	}

	switch level {
	case 1:
		ctx.TrimTrailingWhitespace = true
		ctx.StripBlankLines = true
		ctx.BlobMinHits = 2
		ctx.LargeBlobThresholdBytes = 1024
		ctx.MaxRepeatGroupLines = 16
	case 2:
		ctx.TrimTrailingWhitespace = true
		ctx.StripBlankLines = true
		ctx.StripCommentLines = true
		ctx.BlobMinHits = 2
		ctx.LargeBlobThresholdBytes = 512
		ctx.MaxRepeatGroupLines = 32
		// Helps extract repeated license headers/boilerplate.
		ctx.HeaderBlobMinBytes = 256
		ctx.HeaderBlobMaxBytes = 4096
		ctx.HeaderBlobMaxLines = 80
	case 3:
		ctx.TrimTrailingWhitespace = true
		ctx.StripBlankLines = true
		ctx.StripCommentLines = true
		ctx.BlobMinHits = 2
		ctx.LargeBlobThresholdBytes = 256
		ctx.MaxRepeatGroupLines = 64
		// Slightly more permissive header extraction.
		ctx.HeaderBlobMinBytes = 192
		ctx.HeaderBlobMaxBytes = 8192
		ctx.HeaderBlobMaxLines = 120

		// Aggressive truncation for large blocks (lossy).
		ctx.TruncateMinBytes = 16 * 1024
		ctx.TruncateMinLines = 200
		ctx.TruncateHead = 80
		ctx.TruncateTail = 40
		ctx.TruncateHeadBytes = 4096
		ctx.TruncateTailBytes = 2048
	}

	return ctx, nil
}

func minNonZero(a, b int) int {
	if a <= 0 {
		return b
	}
	if b <= 0 {
		return a
	}
	if a < b {
		return a
	}
	return b
}

type compressionTextKind int

const (
	compressionTextFile compressionTextKind = iota
	compressionTextCommand
)

type commentStyle struct {
	LinePrefixes []string
	BlockStart   string
	BlockEnd     string
}

func (cs commentStyle) empty() bool {
	return len(cs.LinePrefixes) == 0 && cs.BlockStart == "" && cs.BlockEnd == ""
}

func commentStyleForPath(path string) commentStyle {
	base := filepath.Base(path)
	ext := strings.ToLower(filepath.Ext(base))
	lowerBase := strings.ToLower(base)

	switch ext {
	// C/Java/Go-style comments
	case ".go", ".js", ".jsx", ".ts", ".tsx", ".java", ".c", ".cc", ".cpp", ".h", ".hh", ".hpp", ".cs", ".rs", ".swift", ".kt", ".kts":
		return commentStyle{LinePrefixes: []string{"//"}, BlockStart: "/*", BlockEnd: "*/"}
	// Hash comments
	case ".py", ".sh", ".bash", ".zsh", ".rb", ".pl", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf":
		return commentStyle{LinePrefixes: []string{"#"}}
	// SQL-style
	case ".sql":
		return commentStyle{LinePrefixes: []string{"--"}, BlockStart: "/*", BlockEnd: "*/"}
	// HTML-style (also common inside Markdown)
	case ".html", ".htm", ".xml", ".svg", ".md":
		return commentStyle{BlockStart: "<!--", BlockEnd: "-->"}
	}

	// Filenames without extensions
	if lowerBase == "dockerfile" || strings.HasPrefix(lowerBase, "dockerfile.") {
		return commentStyle{LinePrefixes: []string{"#"}}
	}
	if lowerBase == "makefile" || strings.HasSuffix(lowerBase, ".mk") {
		return commentStyle{LinePrefixes: []string{"#"}}
	}

	return commentStyle{}
}

type lossyChanges struct {
	Any        bool
	Whitespace bool
	Comments   bool
}

func containsCommentKeepKeyword(trimmed string) bool {
	up := strings.ToUpper(trimmed)
	return strings.Contains(up, "TODO") || strings.Contains(up, "FIXME") || strings.Contains(up, "BUG") || strings.Contains(up, "HACK") || strings.Contains(up, "XXX")
}

func applyLossyTransforms(s string, ctx *CompressionContext, kind compressionTextKind, pathHint string) (string, lossyChanges) {
	if ctx == nil || !ctx.Enabled {
		return s, lossyChanges{}
	}

	stripComments := ctx.StripCommentLines && kind == compressionTextFile
	trimTrailing := ctx.TrimTrailingWhitespace
	stripBlank := ctx.StripBlankLines

	if !stripComments && !trimTrailing && !stripBlank {
		return s, lossyChanges{}
	}

	cs := commentStyle{}
	if stripComments {
		cs = commentStyleForPath(pathHint)
		if cs.empty() {
			stripComments = false
		}
	}

	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))

	inBlock := false
	changedWhitespace := false
	changedComments := false

	for i, line := range lines {
		if trimTrailing {
			trimmed := strings.TrimRight(line, " \t")
			if trimmed != line {
				changedWhitespace = true
			}
			line = trimmed
		}

		if stripComments && !cs.empty() {
			droppedByComment := false
		reprocess:
			trimmed := strings.TrimSpace(line)
			if inBlock {
				endIdx := strings.Index(line, cs.BlockEnd)
				if endIdx == -1 {
					changedComments = true
					continue
				}

				// Keep anything after the block comment end.
				remainder := line[endIdx+len(cs.BlockEnd):]
				inBlock = false
				changedComments = true
				if strings.TrimSpace(remainder) == "" {
					continue
				}
				line = remainder
				goto reprocess
			}

			if cs.BlockStart != "" && strings.HasPrefix(trimmed, cs.BlockStart) {
				endIdx := strings.Index(line, cs.BlockEnd)
				changedComments = true
				if endIdx == -1 {
					inBlock = true
					continue
				}
				remainder := line[endIdx+len(cs.BlockEnd):]
				if strings.TrimSpace(remainder) == "" {
					continue
				}
				line = remainder
				goto reprocess
			}

			for _, prefix := range cs.LinePrefixes {
				if !strings.HasPrefix(trimmed, prefix) {
					continue
				}

				// Preserve shebangs.
				if prefix == "#" && i == 0 && strings.HasPrefix(trimmed, "#!") {
					break
				}

				// Preserve Go build tags even when stripping comments (useful context).
				if prefix == "//" && (strings.HasPrefix(trimmed, "//go:build") || strings.HasPrefix(trimmed, "// +build")) {
					break
				}

				// Keep TODO/FIXME/etc. comments even in lossy modes.
				if containsCommentKeepKeyword(trimmed) {
					break
				}

				changedComments = true
				droppedByComment = true
				break
			}
			if droppedByComment {
				continue
			}
		}

		if stripBlank && strings.TrimSpace(line) == "" {
			changedWhitespace = true
			continue
		}
		out = append(out, line)
	}

	result := strings.Join(out, "\n")
	if result == s {
		return s, lossyChanges{}
	}
	return result, lossyChanges{
		Any:        true,
		Whitespace: changedWhitespace,
		Comments:   changedComments,
	}
}

func shouldCountHeaderLine(trimmed string, lineIndex int) bool {
	if trimmed == "" {
		return true
	}
	// Shebangs.
	if lineIndex == 0 && strings.HasPrefix(trimmed, "#!") {
		return true
	}
	// Common comment prefixes across many languages.
	if strings.HasPrefix(trimmed, "//") {
		return true
	}
	if strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*/") || strings.HasPrefix(trimmed, "*") {
		return true
	}
	if strings.HasPrefix(trimmed, "<!--") || strings.HasPrefix(trimmed, "-->") {
		return true
	}
	// Treat '# ...' (hash followed by whitespace) as comment; avoid grabbing C preprocessor directives.
	if strings.HasPrefix(trimmed, "#") {
		if len(trimmed) >= 2 && (trimmed[1] == ' ' || trimmed[1] == '\t') {
			return true
		}
		return false
	}
	return false
}

func extractLeadingHeaderBlock(s string, maxLines, maxBytes int) string {
	if maxLines <= 0 || maxBytes <= 0 {
		return ""
	}
	lines := strings.Split(s, "\n")
	var out strings.Builder
	linesUsed := 0
	bytesUsed := 0
	for i, line := range lines {
		if linesUsed >= maxLines || bytesUsed >= maxBytes {
			break
		}
		trimmed := strings.TrimSpace(line)
		if !shouldCountHeaderLine(trimmed, i) {
			break
		}
		// Add the line and newline (if not last) while respecting byte cap.
		lineBytes := len(line)
		if bytesUsed+lineBytes > maxBytes {
			break
		}
		out.WriteString(line)
		bytesUsed += lineBytes
		linesUsed++
		if i < len(lines)-1 {
			if bytesUsed+1 > maxBytes {
				break
			}
			out.WriteString("\n")
			bytesUsed++
		}
	}
	return out.String()
}

func addBlobCandidate(idx map[string]*BlobDef, content string) {
	if len(content) == 0 {
		return
	}
	h := calculateFileHash([]byte(content))
	if existing, ok := idx[h]; ok {
		existing.Count++
	} else {
		idx[h] = &BlobDef{ID: "", Hash: h, Content: content, Count: 1}
	}
}

// buildLargeBlobIndex walks all files and collects repeated blobs across files (and within files).
func buildLargeBlobIndex(entry *FileEntry, ctx *CompressionContext, idx map[string]*BlobDef) {
	if entry == nil {
		return
	}
	if !entry.IsDir {
		if len(entry.Content) == 0 {
			return
		}
		content := string(entry.Content)
		if ctx != nil && ctx.Enabled {
			transformed, _ := applyLossyTransforms(content, ctx, compressionTextFile, entry.Path)
			content = transformed
		}
		paragraphs := extractLargeParagraphs(content, ctx.LargeBlobThresholdBytes)
		for _, p := range paragraphs {
			addBlobCandidate(idx, p)
		}
		if ctx.HeaderBlobMinBytes > 0 {
			header := extractLeadingHeaderBlock(content, ctx.HeaderBlobMaxLines, ctx.HeaderBlobMaxBytes)
			if len(header) >= ctx.HeaderBlobMinBytes {
				addBlobCandidate(idx, header)
			}
		}
		return
	}
	for _, child := range entry.Children {
		buildLargeBlobIndex(child, ctx, idx)
	}
}

// finalizeBlobIDs filters blobs that meet the repetition threshold and assigns stable IDs
func finalizeBlobIDs(idx map[string]*BlobDef, minHits int, minBytes int) (map[string]*BlobDef, map[string]*BlobDef) {
	blobsByID := make(map[string]*BlobDef)
	blobsByHash := make(map[string]*BlobDef)
	for hash, def := range idx {
		if def.Count >= minHits && len(def.Content) >= minBytes {
			id := "blob-" + hash[:8]
			def.ID = id
			blobsByID[id] = def
			blobsByHash[hash] = def
		}
	}
	return blobsByID, blobsByHash
}

// extractLargeParagraphs splits content into paragraphs separated by blank lines
// and returns only those whose byte length >= threshold.
func extractLargeParagraphs(s string, threshold int) []string {
	lines := strings.Split(s, "\n")
	var paragraphs []string
	var current strings.Builder
	for i, line := range lines {
		if strings.TrimSpace(line) == "" { // blank line denotes paragraph boundary
			if current.Len() > 0 {
				para := current.String()
				if len(para) >= threshold {
					paragraphs = append(paragraphs, para)
				}
				current.Reset()
			}
			// keep blank line inside the paragraph boundaries as separator
			continue
		}
		current.WriteString(line)
		// re-add newline if not last line to preserve exact paragraph text
		if i < len(lines)-1 {
			current.WriteString("\n")
		}
	}
	if current.Len() > 0 {
		para := current.String()
		if len(para) >= threshold {
			paragraphs = append(paragraphs, para)
		}
	}
	return paragraphs
}

// replaceLargeBlobs substitutes any known large repeated blob occurrences with a placeholder
func replaceLargeBlobs(s string, ctx *CompressionContext) (string, bool) {
	if ctx == nil || !ctx.Enabled || len(ctx.BlobsByID) == 0 {
		return s, false
	}
	changed := false
	result := s
	ids := ctx.BlobIDs
	if len(ids) == 0 {
		ids = make([]string, 0, len(ctx.BlobsByID))
		for id := range ctx.BlobsByID {
			ids = append(ids, id)
		}
		sort.Strings(ids)
	}
	for _, id := range ids {
		blob := ctx.BlobsByID[id]
		if blob == nil {
			continue
		}
		placeholder := "<<<" + id + ">>>"
		if strings.Contains(result, blob.Content) {
			result = strings.ReplaceAll(result, blob.Content, placeholder)
			ctx.UsedBlobIDs[id] = true
			changed = true
		}
	}
	return result, changed
}

// compressRepeatedBlocks detects consecutive repeated blocks of up to maxRepeatGroupLines lines
// and collapses them to a single block plus an annotation line.
func compressRepeatedBlocks(s string, maxRepeatGroupLines int) (string, bool) {
	lines := strings.Split(s, "\n")
	if len(lines) == 0 {
		return s, false
	}
	if maxRepeatGroupLines <= 0 {
		return s, false
	}
	var out []string
	changed := false
	for i := 0; i < len(lines); {
		remaining := len(lines) - i
		groupMax := maxRepeatGroupLines
		if remaining < groupMax {
			groupMax = remaining
		}
		compressedHere := false
		for groupSize := groupMax; groupSize >= 1; groupSize-- {
			if i+groupSize > len(lines) {
				continue
			}
			block := lines[i : i+groupSize]
			repeats := 1
			j := i + groupSize
			for j+groupSize <= len(lines) {
				candidate := lines[j : j+groupSize]
				match := true
				for k := 0; k < groupSize; k++ {
					if candidate[k] != block[k] {
						match = false
						break
					}
				}
				if !match {
					break
				}
				repeats++
				j += groupSize
			}
			if repeats >= 2 {
				out = append(out, block...)
				out = append(out, fmt.Sprintf("(...<<<repeats %d times, %d lines>>>...)", repeats, groupSize))
				i = i + repeats*groupSize
				changed = true
				compressedHere = true
				break
			}
		}
		if !compressedHere {
			out = append(out, lines[i])
			i++
		}
	}
	return strings.Join(out, "\n"), changed
}

func maybeTruncateText(s string, ctx *CompressionContext) (string, bool) {
	if ctx == nil || !ctx.Enabled {
		return s, false
	}
	if ctx.TruncateMinLines <= 0 && ctx.TruncateMinBytes <= 0 {
		return s, false
	}

	wantsByteTrunc := ctx.TruncateMinBytes > 0 && len(s) >= ctx.TruncateMinBytes

	// Only count lines when needed.
	lineCount := 1
	if ctx.TruncateMinLines > 0 || !wantsByteTrunc {
		lineCount = strings.Count(s, "\n") + 1
	}
	wantsLineTrunc := ctx.TruncateMinLines > 0 && lineCount >= ctx.TruncateMinLines

	if !wantsLineTrunc && !wantsByteTrunc {
		return s, false
	}

	// Prefer line-based truncation when it applies and would actually reduce output.
	if wantsLineTrunc && ctx.TruncateHead > 0 && ctx.TruncateTail >= 0 {
		lines := strings.Split(s, "\n")
		if ctx.TruncateHead+ctx.TruncateTail+1 < len(lines) {
			return truncateByLines(lines, ctx.TruncateHead, ctx.TruncateTail), true
		}
	}

	if wantsByteTrunc && ctx.TruncateHeadBytes > 0 && ctx.TruncateTailBytes > 0 {
		return truncateByBytes(s, ctx.TruncateHeadBytes, ctx.TruncateTailBytes)
	}

	return s, false
}

func truncateByLines(lines []string, head, tail int) string {
	if head < 0 {
		head = 0
	}
	if tail < 0 {
		tail = 0
	}
	if head+tail+1 >= len(lines) {
		return strings.Join(lines, "\n")
	}
	omitted := len(lines) - head - tail
	out := make([]string, 0, head+tail+1)
	if head > 0 {
		out = append(out, lines[:head]...)
	}
	out = append(out, fmt.Sprintf("(...<<<omitted %d lines>>>...)", omitted))
	if tail > 0 {
		out = append(out, lines[len(lines)-tail:]...)
	}
	return strings.Join(out, "\n")
}

func truncateByBytes(s string, head, tail int) (string, bool) {
	if head < 0 {
		head = 0
	}
	if tail < 0 {
		tail = 0
	}
	if head == 0 || tail == 0 {
		return s, false
	}
	if head+tail+1 >= len(s) {
		return s, false
	}
	omitted := len(s) - head - tail
	truncated := s[:head] + fmt.Sprintf("\n(...<<<omitted %d bytes>>>...)\n", omitted) + s[len(s)-tail:]
	return truncated, true
}

func isLikelyCodeFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".go", ".rs", ".py", ".rb", ".php", ".java", ".kt", ".kts", ".swift", ".c", ".cc", ".cpp", ".h", ".hh", ".hpp", ".cs", ".m", ".mm", ".js", ".jsx", ".ts", ".tsx":
		return true
	case ".sh", ".bash", ".zsh", ".ps1":
		return true
	}
	return false
}

type outlineStyle struct {
	Prefixes  []string
	MaxIndent int // -1 means any
}

func outlineStyleForPath(path string) outlineStyle {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".go":
		return outlineStyle{Prefixes: []string{"package ", "import ", "type ", "func ", "const ", "var "}, MaxIndent: 0}
	case ".py":
		return outlineStyle{Prefixes: []string{"def ", "class ", "async def "}, MaxIndent: 8}
	case ".rs":
		return outlineStyle{Prefixes: []string{"fn ", "pub ", "struct ", "enum ", "trait ", "impl ", "type ", "const ", "mod ", "use "}, MaxIndent: 0}
	case ".js", ".jsx", ".ts", ".tsx":
		return outlineStyle{Prefixes: []string{"export ", "function ", "class ", "interface ", "type ", "const ", "let ", "var ", "enum "}, MaxIndent: 0}
	case ".java", ".kt", ".kts", ".cs", ".swift", ".c", ".cc", ".cpp", ".h", ".hh", ".hpp":
		return outlineStyle{Prefixes: []string{"class ", "interface ", "enum ", "struct ", "func ", "def ", "public ", "private ", "protected ", "static "}, MaxIndent: 0}
	case ".sh", ".bash", ".zsh":
		return outlineStyle{Prefixes: []string{"function ", "export ", "readonly "}, MaxIndent: 0}
	}
	return outlineStyle{}
}

func ellipsize(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

func extractOutlineLines(lines []string, path string, start, end, max int) []string {
	if start < 0 {
		start = 0
	}
	if end <= 0 || end > len(lines) {
		end = len(lines)
	}
	if start >= end {
		return nil
	}

	style := outlineStyleForPath(path)
	if len(style.Prefixes) == 0 {
		return nil
	}

	out := make([]string, 0, minNonZero(max, 64))
	truncated := false

	for i := start; i < end; i++ {
		raw := lines[i]
		if style.MaxIndent >= 0 {
			indent := len(raw) - len(strings.TrimLeft(raw, " \t"))
			if indent > style.MaxIndent {
				continue
			}
		}

		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		switch trimmed {
		case "{", "}", "(", ")", "[", "]":
			continue
		}
		match := false
		for _, p := range style.Prefixes {
			if strings.HasPrefix(trimmed, p) {
				match = true
				break
			}
		}
		if !match {
			continue
		}

		out = append(out, fmt.Sprintf("L%d: %s", i+1, ellipsize(trimmed, 200)))
		if max > 0 && len(out) >= max {
			truncated = true
			break
		}
	}
	if len(out) == 0 {
		return nil
	}
	if truncated {
		out = append(out, "(...<<<outline truncated>>>...)")
	}
	return out
}

func maybeTruncateTextWithOutline(s string, ctx *CompressionContext, kind compressionTextKind, pathHint string) (string, bool, bool) {
	if ctx == nil || !ctx.Enabled {
		return s, false, false
	}
	if ctx.TruncateMinLines <= 0 && ctx.TruncateMinBytes <= 0 {
		return s, false, false
	}

	wantsByteTrunc := ctx.TruncateMinBytes > 0 && len(s) >= ctx.TruncateMinBytes

	// Only count lines when needed.
	lineCount := 1
	if ctx.TruncateMinLines > 0 || !wantsByteTrunc {
		lineCount = strings.Count(s, "\n") + 1
	}
	wantsLineTrunc := ctx.TruncateMinLines > 0 && lineCount >= ctx.TruncateMinLines

	if !wantsLineTrunc && !wantsByteTrunc {
		return s, false, false
	}

	if kind == compressionTextFile && ctx.Level >= 3 && strings.TrimSpace(pathHint) != "" && wantsLineTrunc {
		lines := strings.Split(s, "\n")
		if ctx.TruncateHead > 0 && ctx.TruncateTail >= 0 && ctx.TruncateHead+ctx.TruncateTail+1 < len(lines) {
			head := ctx.TruncateHead
			tail := ctx.TruncateTail
			if isLikelyCodeFile(pathHint) {
				// In code, tail is usually closing braces/noise; prefer an outline of omitted content.
				tail = 0
			}
			start := head
			end := len(lines) - tail
			outline := extractOutlineLines(lines, pathHint, start, end, 200)
			if isLikelyCodeFile(pathHint) && len(outline) > 0 {
				out := make([]string, 0, head+len(outline)+8)
				if head > 0 {
					out = append(out, lines[:head]...)
				}
				omitted := len(lines) - head - tail
				out = append(out, fmt.Sprintf("(...<<<omitted %d lines; outline below>>>...)", omitted))
				out = append(out, "<<<outline>>>")
				out = append(out, outline...)
				out = append(out, "<<<end-outline>>>")
				if tail > 0 {
					out = append(out, lines[len(lines)-tail:]...)
				}
				return strings.Join(out, "\n"), true, true
			}
		}
	}

	truncated, changed := maybeTruncateText(s, ctx)
	return truncated, changed, false
}

func addLineNumbers(s string) string {
	if s == "" {
		return ""
	}

	lines := strings.Split(s, "\n")
	if strings.HasSuffix(s, "\n") && len(lines) > 0 {
		lines = lines[:len(lines)-1]
	}
	if len(lines) == 0 {
		return ""
	}

	width := len(strconv.Itoa(len(lines)))
	var b strings.Builder
	b.Grow(len(s) + len(lines)*(width+3))
	for i, line := range lines {
		fmt.Fprintf(&b, "%*d | %s", width, i+1, line)
		if i < len(lines)-1 {
			b.WriteString("\n")
		}
	}
	return b.String()
}

func printFlattenedOutput(entry *FileEntry, w *strings.Builder, fileHashes map[string]*FileHash, showTokens bool, delimiter string, compCtx *CompressionContext, sections *[]OutputSection) {
	if !entry.IsDir {
		start := 0
		if sections != nil {
			start = w.Len()
		}
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
		if entry.ReadError != "" {
			w.WriteString(fmt.Sprintf("- read-error: %s\n", entry.ReadError))
			if showAllMetadata || showOwnership {
				getOwnershipInfo(entry.Path, w)
			}
			if showAllMetadata || showChecksum {
				w.WriteString("- sha256: (unavailable)\n")
			}
			if showTokens {
				w.WriteString(fmt.Sprintf("- tokens: %d\n", entry.Tokens))
			}
			contentStr := fmt.Sprintf("(unreadable: %s)", entry.ReadError)
			if showLineNumbers {
				contentStr = addLineNumbers(contentStr)
			}
			w.WriteString(fmt.Sprintf("- content:\n%s\n%s\n%s\n", delimiter, contentStr, delimiter))
			if sections != nil {
				*sections = append(*sections, OutputSection{Label: entry.Path, Start: start, End: w.Len()})
			}
			return
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
		contentStr := string(entry.Content)
		// Apply compression strategies when enabled
		if compCtx != nil && compCtx.Enabled {
			if transformed, changes := applyLossyTransforms(contentStr, compCtx, compressionTextFile, entry.Path); changes.Any {
				contentStr = transformed
				compCtx.Applied = true
				if changes.Whitespace {
					compCtx.AppliedWhitespace = true
				}
				if changes.Comments {
					compCtx.AppliedComments = true
				}
			}
			if replaced, changed := replaceLargeBlobs(contentStr, compCtx); changed {
				contentStr = replaced
				compCtx.Applied = true
				compCtx.AppliedBlobs = true
			}
			if compressed, changed := compressRepeatedBlocks(contentStr, compCtx.MaxRepeatGroupLines); changed {
				contentStr = compressed
				compCtx.Applied = true
				compCtx.AppliedRepeats = true
			}
			if truncated, changed, outlined := maybeTruncateTextWithOutline(contentStr, compCtx, compressionTextFile, entry.Path); changed {
				contentStr = truncated
				compCtx.Applied = true
				compCtx.AppliedTruncation = true
				if outlined {
					compCtx.AppliedOutline = true
				}
			}
		}
		if showLineNumbers {
			contentStr = addLineNumbers(contentStr)
		}
		if noFileDeduplication {
			w.WriteString(fmt.Sprintf("- content:\n%s\n%s\n%s\n", delimiter, contentStr, delimiter))
			if sections != nil {
				*sections = append(*sections, OutputSection{Label: entry.Path, Start: start, End: w.Len()})
			}
			return
		}
		// Deduplicate based on the original file bytes, not the (possibly compressed) rendered output.
		hash := calculateFileHash(entry.Content)
		if existing, exists := fileHashes[hash]; exists {
			w.WriteString(fmt.Sprintf("- content: Contents are identical to %s\n", existing.Path))
		} else {
			fileHashes[hash] = &FileHash{Path: entry.Path, Hash: hash, Content: entry.Content}
			w.WriteString(fmt.Sprintf("- content:\n%s\n%s\n%s\n", delimiter, contentStr, delimiter))
		}
		if sections != nil {
			*sections = append(*sections, OutputSection{Label: entry.Path, Start: start, End: w.Len()})
		}
		return
	}
	if showTokens {
		start := 0
		if sections != nil {
			start = w.Len()
		}
		w.WriteString(fmt.Sprintf("\n- path: %s\n", entry.Path))
		w.WriteString(fmt.Sprintf("- dir tokens: %d\n", entry.Tokens))
		if sections != nil {
			*sections = append(*sections, OutputSection{Label: entry.Path, Start: start, End: w.Len()})
		}
	}
	for _, child := range entry.Children {
		printFlattenedOutput(child, w, fileHashes, showTokens, delimiter, compCtx, sections)
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

func composeFinalOutput(content string, prefix string, suffix string) string {
	hasPrefix := strings.TrimSpace(prefix) != ""
	hasSuffix := strings.TrimSpace(suffix) != ""

	var out strings.Builder
	if hasPrefix {
		out.WriteString(prefix)
		out.WriteString("\n")
	}
	if hasPrefix || hasSuffix {
		out.WriteString("---\n")
	}
	out.WriteString(content)
	if hasPrefix || hasSuffix {
		out.WriteString("---\n")
	}
	if hasSuffix {
		out.WriteString(suffix)
		out.WriteString("\n")
	}
	return out.String()
}

func fillSectionGaps(sections []OutputSection, totalLen int) []OutputSection {
	if totalLen < 0 {
		totalLen = 0
	}
	if len(sections) == 0 {
		return []OutputSection{{Label: "[all]", Start: 0, End: totalLen}}
	}
	sort.Slice(sections, func(i, j int) bool {
		if sections[i].Start == sections[j].Start {
			return sections[i].End < sections[j].End
		}
		return sections[i].Start < sections[j].Start
	})

	out := make([]OutputSection, 0, len(sections)+2)
	cursor := 0
	for _, s := range sections {
		if s.End <= s.Start {
			continue
		}
		if s.Start > cursor {
			out = append(out, OutputSection{Label: "[other]", Start: cursor, End: s.Start})
		}
		if s.Start < cursor {
			s.Start = cursor
		}
		if s.End <= s.Start {
			continue
		}
		out = append(out, s)
		cursor = s.End
	}
	if cursor < totalLen {
		out = append(out, OutputSection{Label: "[other]", Start: cursor, End: totalLen})
	}
	if len(out) > 0 && out[0].Start != 0 {
		out = append([]OutputSection{{Label: "[other]", Start: 0, End: out[0].Start}}, out...)
	}
	return out
}

func tokenCountsBySection(tkm *tiktoken.Tiktoken, tokens []int, sections []OutputSection) (int, map[string]int) {
	counts := make(map[string]int, len(sections))
	if len(sections) == 0 {
		return len(tokens), counts
	}

	sectionIdx := 0
	byteOffset := 0
	single := make([]int, 1)
	for _, tok := range tokens {
		for sectionIdx < len(sections) && byteOffset >= sections[sectionIdx].End {
			sectionIdx++
		}
		label := "[unattributed]"
		if sectionIdx < len(sections) && byteOffset >= sections[sectionIdx].Start && byteOffset < sections[sectionIdx].End {
			label = sections[sectionIdx].Label
		}
		counts[label]++
		single[0] = tok
		byteOffset += len(tkm.Decode(single))
	}
	return len(tokens), counts
}

func collectNodePaths(entry *FileEntry, filePaths map[string]bool, dirPaths map[string]bool) {
	if entry == nil {
		return
	}
	if entry.IsDir {
		if dirPaths != nil {
			dirPaths[entry.Path] = true
		}
		for _, child := range entry.Children {
			collectNodePaths(child, filePaths, dirPaths)
		}
		return
	}
	if filePaths != nil {
		filePaths[entry.Path] = true
	}
}

func computeSubtreeTokenStats(entry *FileEntry, sectionTokens map[string]int, subtreeTokens map[string]int, subtreeFiles map[string]int) (int, int) {
	if entry == nil {
		return 0, 0
	}
	totalTokens := 0
	if sectionTokens != nil {
		totalTokens = sectionTokens[entry.Path]
	}
	if !entry.IsDir {
		if subtreeTokens != nil {
			subtreeTokens[entry.Path] = totalTokens
		}
		if subtreeFiles != nil {
			subtreeFiles[entry.Path] = 1
		}
		return totalTokens, 1
	}

	totalFiles := 0
	for _, child := range entry.Children {
		ct, cf := computeSubtreeTokenStats(child, sectionTokens, subtreeTokens, subtreeFiles)
		totalTokens += ct
		totalFiles += cf
	}
	if subtreeTokens != nil {
		subtreeTokens[entry.Path] = totalTokens
	}
	if subtreeFiles != nil {
		subtreeFiles[entry.Path] = totalFiles
	}
	return totalTokens, totalFiles
}

func formatDirPathForReport(path string) string {
	if path == "." || path == string(os.PathSeparator) {
		return path
	}
	sep := string(os.PathSeparator)
	if strings.HasSuffix(path, sep) {
		return path
	}
	return path + sep
}

func formatPercent(n int, total int) string {
	if total <= 0 {
		return "0.0%"
	}
	return fmt.Sprintf("%.1f%%", (float64(n)/float64(total))*100.0)
}

// printFinalOutput prints optional prefix, then wraps only the main content
// with --- lines, and finally prints optional suffix. If either prefix or
// suffix is provided, the content is surrounded by --- lines. The prefix has
// --- only after it; the suffix has --- only before it.
func printFinalOutput(content string, prefix, suffix string) {
	fmt.Print(composeFinalOutput(content, prefix, suffix))
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
	Version:      version,
	Args:         cobra.ArbitraryArgs,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			args = []string{"."}
		}

		effectiveCompressLevel := compressLevel
		if !cmd.Flags().Changed("compress-level") && effectiveCompressLevel == 0 && compressOutput {
			effectiveCompressLevel = 1
		}
		if effectiveCompressLevel < 0 || effectiveCompressLevel > 3 {
			return fmt.Errorf("--compress-level must be between 0 and 3")
		}

		defaultOutputMode := outputModePrint
		if cfgMode, err := readHomeDefaultOutputMode(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: %v\n", err)
		} else if cfgMode != "" {
			defaultOutputMode = cfgMode
		}

		mode, err := resolveOutputMode(defaultOutputMode, outputPrint, outputCopy, outputSSHCopy)
		if err != nil {
			return err
		}

		if setDefaultOutput {
			if err := writeHomeDefaultOutputMode(mode); err != nil {
				return err
			}
		}

		autoTcountDetailed := (mode == outputModeCopy || mode == outputModeSSHCopy) && !silent && !dryRun
		effectiveTcountDetailed := tcountDetailed || autoTcountDetailed
		effectiveTcount := tcount || effectiveTcountDetailed

		if effectiveTcount && dryRun {
			return fmt.Errorf("--tcount/--tcount-detailed cannot be used with --dry-run")
		}
		if showTokens && dryRun {
			return fmt.Errorf("--tokens cannot be used with --dry-run")
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
		var sections []OutputSection
		sectionsPtr := (*[]OutputSection)(nil)
		if effectiveTcountDetailed {
			sectionsPtr = &sections
		}

		// Create a root entry that will contain all directories
		root := &FileEntry{
			Path:     ".",
			IsDir:    true,
			Children: make([]*FileEntry, 0),
		}

		profileExplicit := cmd.Flags().Changed("profile")

		// Process each directory and add it to the root
		for _, dir := range args {
			// Surface common --profile typos by warning when the top-level .flatten
			// defines profiles but the requested one is missing.
			if profileExplicit {
				flattenPath := filepath.Join(dir, flattenFileName)
				info, err := os.Stat(flattenPath)
				switch {
				case err == nil && !info.IsDir():
					hasProfiles, hasProfile, hasDefault, err := flattenFileProfileInfo(flattenPath, profileName)
					if err != nil {
						return fmt.Errorf("failed to parse %s: %w", flattenPath, err)
					}
					if hasProfiles && !hasProfile {
						if hasDefault {
							fmt.Fprintf(os.Stderr, "warning: profile %q not found in %s; using profiles.default\n", profileName, flattenPath)
						} else {
							fmt.Fprintf(os.Stderr, "warning: profile %q not found in %s; using base include/exclude rules\n", profileName, flattenPath)
						}
					}
				case err != nil && !os.IsNotExist(err) && !errors.Is(err, fs.ErrPermission):
					return fmt.Errorf("failed to stat %s: %w", flattenPath, err)
				}
			}

			filter, err := NewFilter(dir, includeGitIgnore, includeGit, includeBin, includeLocks, includePatterns, excludePatterns, profileName)
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

		var outputStr string
		var finalStr string
		var legendStr string
		var blobsStr string
		var blobSections []OutputSection

		if dryRun {
			// Dry-run mode: just list the files that would be included
			output.WriteString(fmt.Sprintf("Files that would be included in flatten output:\n\n"))
			output.WriteString(fmt.Sprintf("Total files: %d\n", getTotalFiles(root)))
			if showTotalSize {
				output.WriteString(fmt.Sprintf("Total size: %d bytes\n", getTotalSize(root)))
			}
			output.WriteString(fmt.Sprintf("\nDirectory structure:\n%s\n", renderDirTreeForOutput(root, false)))
			output.WriteString("Files:\n")
			printDryRunOutput(root, &output)
			outputStr = output.String()
			finalStr = outputStr
		} else {
			if showTokens {
				sumTokens(root)
			}

			// Write a single map for all directories
			headerStart := output.Len()
			output.WriteString(fmt.Sprintf("Total files: %d\n", getTotalFiles(root)))
			if showTotalSize {
				output.WriteString(fmt.Sprintf("Total size: %d bytes\n", getTotalSize(root)))
			}
			output.WriteString(fmt.Sprintf("Directory structure:\n%s\n", renderDirTreeForOutput(root, showTokens)))
			if sectionsPtr != nil {
				*sectionsPtr = append(*sectionsPtr, OutputSection{Label: "[header]", Start: headerStart, End: output.Len()})
			}

			// If commands were requested, run them now so their outputs can be included
			// in delimiter auto-detection and compression blob indexing while preserving
			// the final print order below.
			var cmdResults []CommandResult
			if len(commands) > 0 {
				cmdResults = runCommands(commands)
			}

			// Determine the markdown delimiter
			delimiter := markdownDelimiter
			if delimiter == "auto" {
				delimiter = detectBestDelimiter(root, cmdResults)
			}

			fileHashes := make(map[string]*FileHash)

			// Prepare compression context when enabled
			var compCtx *CompressionContext
			if effectiveCompressLevel > 0 {
				var err error
				compCtx, err = newCompressionContext(effectiveCompressLevel)
				if err != nil {
					return err
				}
				// build global index for large repeated blobs across files and command outputs
				tempIdx := make(map[string]*BlobDef)
				buildLargeBlobIndex(root, compCtx, tempIdx)
				// include command outputs in the blob index
				for _, r := range cmdResults {
					stdoutStr, _ := applyLossyTransforms(r.Stdout, compCtx, compressionTextCommand, "")
					for _, block := range extractLargeParagraphs(stdoutStr, compCtx.LargeBlobThresholdBytes) {
						addBlobCandidate(tempIdx, block)
					}
					stderrStr, _ := applyLossyTransforms(r.Stderr, compCtx, compressionTextCommand, "")
					for _, block := range extractLargeParagraphs(stderrStr, compCtx.LargeBlobThresholdBytes) {
						addBlobCandidate(tempIdx, block)
					}
				}
				minBytes := minNonZero(compCtx.LargeBlobThresholdBytes, compCtx.HeaderBlobMinBytes)
				blobsByID, blobsByHash := finalizeBlobIDs(tempIdx, compCtx.BlobMinHits, minBytes)
				blobIDs := make([]string, 0, len(blobsByID))
				for id := range blobsByID {
					blobIDs = append(blobIDs, id)
				}
				sort.Slice(blobIDs, func(i, j int) bool {
					li := 0
					lj := 0
					if def := blobsByID[blobIDs[i]]; def != nil {
						li = len(def.Content)
					}
					if def := blobsByID[blobIDs[j]]; def != nil {
						lj = len(def.Content)
					}
					if li == lj {
						return blobIDs[i] < blobIDs[j]
					}
					return li > lj
				})
				compCtx.BlobsByID = blobsByID
				compCtx.BlobsByHash = blobsByHash
				compCtx.BlobIDs = blobIDs
			}

			printFlattenedOutput(root, &output, fileHashes, showTokens, delimiter, compCtx, sectionsPtr)

			// If commands were requested, run them and append a detailed report
			if len(commands) > 0 {
				if sectionsPtr != nil {
					start := output.Len()
					output.WriteString("\nCommands execution:\n")
					*sectionsPtr = append(*sectionsPtr, OutputSection{Label: "[commands]", Start: start, End: output.Len()})
				} else {
					output.WriteString("\nCommands execution:\n")
				}
				for _, r := range cmdResults {
					cmdStart := output.Len()
					output.WriteString(fmt.Sprintf("\n- command: %s\n", r.Command))
					output.WriteString(fmt.Sprintf("- started: %s\n", r.StartTime.Format(time.RFC3339Nano)))
					output.WriteString(fmt.Sprintf("- finished: %s\n", r.EndTime.Format(time.RFC3339Nano)))
					output.WriteString(fmt.Sprintf("- duration: %s\n", r.Duration))
					output.WriteString(fmt.Sprintf("- exit-code: %d\n", r.ExitCode))
					if r.Stdout != "" {
						stdoutStr := r.Stdout
						if compCtx != nil && compCtx.Enabled {
							if transformed, changes := applyLossyTransforms(stdoutStr, compCtx, compressionTextCommand, ""); changes.Any {
								stdoutStr = transformed
								compCtx.Applied = true
								if changes.Whitespace {
									compCtx.AppliedWhitespace = true
								}
							}
							if replaced, changed := replaceLargeBlobs(stdoutStr, compCtx); changed {
								stdoutStr = replaced
								compCtx.Applied = true
								compCtx.AppliedBlobs = true
							}
							if compressed, changed := compressRepeatedBlocks(stdoutStr, compCtx.MaxRepeatGroupLines); changed {
								stdoutStr = compressed
								compCtx.Applied = true
								compCtx.AppliedRepeats = true
							}
							if truncated, changed, outlined := maybeTruncateTextWithOutline(stdoutStr, compCtx, compressionTextCommand, ""); changed {
								stdoutStr = truncated
								compCtx.Applied = true
								compCtx.AppliedTruncation = true
								if outlined {
									compCtx.AppliedOutline = true
								}
							}
						}
						if showLineNumbers {
							stdoutStr = addLineNumbers(stdoutStr)
						}
						output.WriteString(fmt.Sprintf("- stdout:\n%s\n%s\n%s\n", delimiter, stdoutStr, delimiter))
					} else {
						output.WriteString("- stdout: (empty)\n")
					}
					if r.Stderr != "" {
						stderrStr := r.Stderr
						if compCtx != nil && compCtx.Enabled {
							if transformed, changes := applyLossyTransforms(stderrStr, compCtx, compressionTextCommand, ""); changes.Any {
								stderrStr = transformed
								compCtx.Applied = true
								if changes.Whitespace {
									compCtx.AppliedWhitespace = true
								}
							}
							if replaced, changed := replaceLargeBlobs(stderrStr, compCtx); changed {
								stderrStr = replaced
								compCtx.Applied = true
								compCtx.AppliedBlobs = true
							}
							if compressed, changed := compressRepeatedBlocks(stderrStr, compCtx.MaxRepeatGroupLines); changed {
								stderrStr = compressed
								compCtx.Applied = true
								compCtx.AppliedRepeats = true
							}
							if truncated, changed, outlined := maybeTruncateTextWithOutline(stderrStr, compCtx, compressionTextCommand, ""); changed {
								stderrStr = truncated
								compCtx.Applied = true
								compCtx.AppliedTruncation = true
								if outlined {
									compCtx.AppliedOutline = true
								}
							}
						}
						if showLineNumbers {
							stderrStr = addLineNumbers(stderrStr)
						}
						output.WriteString(fmt.Sprintf("- stderr:\n%s\n%s\n%s\n", delimiter, stderrStr, delimiter))
					} else {
						output.WriteString("- stderr: (empty)\n")
					}
					if sectionsPtr != nil {
						*sectionsPtr = append(*sectionsPtr, OutputSection{Label: "[command] " + r.Command, Start: cmdStart, End: output.Len()})
					}
				}
			}

			// If compression applied, prepend a tiny legend and append extracted blobs
			outputStr = output.String()
			finalStr = outputStr
			if compCtx != nil && compCtx.Applied {
				var legend strings.Builder
				features := make([]string, 0, 6)
				if compCtx.AppliedWhitespace {
					features = append(features, "blank-lines")
				}
				if compCtx.AppliedComments {
					features = append(features, "comments")
				}
				if compCtx.AppliedRepeats {
					features = append(features, "repeats")
				}
				if compCtx.AppliedBlobs {
					features = append(features, "blobs")
				}
				if compCtx.AppliedTruncation {
					features = append(features, "truncation")
				}
				if compCtx.AppliedOutline {
					features = append(features, "outline")
				}
				legend.WriteString(fmt.Sprintf("Compression: level %d (%s)\n\n", compCtx.Level, strings.Join(features, ", ")))
				legendStr = legend.String()

				// Append blobs section only for used IDs
				var blobsSection strings.Builder
				blobHeaderStart := blobsSection.Len()
				blobsSection.WriteString("\nExtracted blobs:\n")
				if sectionsPtr != nil {
					blobSections = append(blobSections, OutputSection{Label: "[blobs]", Start: blobHeaderStart, End: blobsSection.Len()})
				}
				anyBlob := false
				usedIDs := make([]string, 0, len(compCtx.UsedBlobIDs))
				for id := range compCtx.UsedBlobIDs {
					usedIDs = append(usedIDs, id)
				}
				sort.Slice(usedIDs, func(i, j int) bool {
					li := 0
					lj := 0
					if def := compCtx.BlobsByID[usedIDs[i]]; def != nil {
						li = len(def.Content)
					}
					if def := compCtx.BlobsByID[usedIDs[j]]; def != nil {
						lj = len(def.Content)
					}
					if li == lj {
						return usedIDs[i] < usedIDs[j]
					}
					return li > lj
				})
				for _, id := range usedIDs {
					if def, ok := compCtx.BlobsByID[id]; ok {
						anyBlob = true
						blobStart := blobsSection.Len()
						blobsSection.WriteString(fmt.Sprintf("\n- id: %s\n", id))
						blobsSection.WriteString("- content:\n")
						blobContent := def.Content
						if compCtx.Level >= 3 {
							if truncated, changed, outlined := maybeTruncateTextWithOutline(blobContent, compCtx, compressionTextFile, ""); changed {
								blobContent = truncated
								compCtx.AppliedTruncation = true
								if outlined {
									compCtx.AppliedOutline = true
								}
							}
						}
						blobsSection.WriteString(fmt.Sprintf("%s\n%s\n%s\n", delimiter, blobContent, delimiter))
						if sectionsPtr != nil {
							blobSections = append(blobSections, OutputSection{Label: "[blob] " + id, Start: blobStart, End: blobsSection.Len()})
						}
					}
				}
				if anyBlob {
					blobsStr = blobsSection.String()
				} else {
					blobsStr = ""
					blobSections = nil
				}

				finalStr = legendStr + outputStr + blobsStr
			}
		}

		needsPrintedOutput := mode != outputModePrint || effectiveTcount
		printed := ""
		if needsPrintedOutput {
			printed = composeFinalOutput(finalStr, prefixMessage, suffixMessage)
		}

		tokenReport := ""
		if effectiveTcount {
			model := tokensModel
			if strings.TrimSpace(tcountModel) != "" {
				model = tcountModel
			}
			sectionsEnabled := sectionsPtr != nil
			report, err := buildTokenReport(printed, model, effectiveTcountDetailed, sections, sectionsEnabled, legendStr, outputStr, blobsStr, blobSections, root, prefixMessage, suffixMessage)
			if err != nil {
				return err
			}
			tokenReport = report
		}

		switch mode {
		case outputModePrint:
			if effectiveTcount {
				if !silent {
					fmt.Print(tokenReport)
				}
				return nil
			}
			printFinalOutput(finalStr, prefixMessage, suffixMessage)
			return nil
		case outputModeCopy:
			if err := copyToClipboard(printed); err != nil {
				return err
			}
			if effectiveTcount && !silent {
				fmt.Print(tokenReport)
			}
			return nil
		case outputModeSSHCopy:
			if err := copyToOSC52(printed); err != nil {
				return err
			}
			if effectiveTcount && !silent {
				fmt.Print(tokenReport)
			}
			return nil
		default:
			return fmt.Errorf("unknown output mode %q", mode)
		}
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

	rootCmd.Flags().BoolVar(&showLineNumbers, "line-numbers", false, "Include line numbers in file and command output content")

	rootCmd.Flags().BoolVarP(&showTokens, "tokens", "t", false, "Show token usage for each file/directory")
	rootCmd.Flags().StringVar(&tokensModel, "tokens-model", "gpt-4o-mini", "Model to use for --tokens (per-file token counting)")

	rootCmd.Flags().BoolVar(&tcount, "tcount", false, "Print token count of the full output (equivalent to: flatten | tcount)")
	rootCmd.Flags().BoolVar(&tcountDetailed, "tcount-detailed", false, "Print token count and a breakdown of token usage by path/section")
	rootCmd.Flags().StringVar(&tcountModel, "tcount-model", "", "Model to use for token-counting the full output (defaults to --tokens-model)")

	rootCmd.Flags().StringSliceVarP(&includePatterns, "include", "I", []string{}, "Include only files matching these patterns (e.g. '*.go,*.js')")
	rootCmd.Flags().StringSliceVarP(&excludePatterns, "exclude", "E", []string{}, "Exclude files matching these patterns (e.g. '*.test.js')")
	rootCmd.Flags().StringVarP(&profileName, "profile", "p", "default", "Profile to use when reading .flatten files")

	rootCmd.Flags().StringVar(&markdownDelimiter, "markdown-delimiter", "auto", "Markdown code block delimiter (auto, <3 backticks>, ~~~, <5 backticks>, ~~~~~, ~~~~~~~~~~~)")
	rootCmd.Flags().BoolVarP(&dryRun, "dry-run", "d", false, "List all files that would be included without processing content")

	rootCmd.Flags().BoolVar(&outputPrint, "print", false, "Print output to stdout (default)")
	rootCmd.Flags().BoolVar(&outputCopy, "copy", false, "Copy output to the system clipboard")
	rootCmd.Flags().BoolVar(&outputSSHCopy, "ssh-copy", false, "Copy output to the terminal clipboard over SSH using osc52")
	rootCmd.Flags().BoolVar(&silent, "silent", false, "Suppress token report output (useful with --copy/--ssh-copy)")
	rootCmd.Flags().BoolVar(&setDefaultOutput, "set-default", false, "Persist the selected output mode to ~/.flatten")

	// Output compression flag (disabled by default)
	rootCmd.Flags().BoolVar(&compressOutput, "compress", false, "Compress output by collapsing repeats and extracting large repeated blobs")
	rootCmd.Flags().IntVar(&compressLevel, "compress-level", 0, "Compression level (0=off, 1=default, 2=more, 3=most aggressive)")

	// Allow specifying any number of commands. Each --command is executed after flattening.
	rootCmd.Flags().StringArrayVar(&commands, "command", []string{}, "Command to run after flattening (can be repeated)")

	// Optional prefix/suffix wrappers
	rootCmd.Flags().StringVar(&prefixMessage, "prefix", "", "Optional message printed before output, wrapped by --- lines")
	rootCmd.Flags().StringVar(&suffixMessage, "suffix", "", "Optional message printed after output, wrapped by --- lines")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
