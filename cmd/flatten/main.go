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

	showTokens  bool
	tokensModel string

	tcount         bool
	tcountDetailed bool
	tcountModel    string

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
	Enabled     bool
	BlobsByID   map[string]*BlobDef
	BlobsByHash map[string]*BlobDef
	BlobIDs     []string
	UsedBlobIDs map[string]bool
	Applied     bool
}

const largeBlobThresholdBytes = 1024 // "sane" threshold for large repeated blobs
const maxRepeatGroupLines = 16       // max group size to detect repeated line blocks

// buildLargeBlobIndex walks all files and collects large repeated paragraphs across files
func buildLargeBlobIndex(entry *FileEntry, idx map[string]*BlobDef) {
	if entry == nil {
		return
	}
	if !entry.IsDir {
		if len(entry.Content) == 0 {
			return
		}
		content := string(entry.Content)
		paragraphs := extractLargeParagraphs(content, largeBlobThresholdBytes)
		for _, p := range paragraphs {
			h := calculateFileHash([]byte(p))
			if existing, ok := idx[h]; ok {
				existing.Count++
			} else {
				idx[h] = &BlobDef{ID: "", Hash: h, Content: p, Count: 1}
			}
		}
		return
	}
	for _, child := range entry.Children {
		buildLargeBlobIndex(child, idx)
	}
}

// finalizeBlobIDs filters blobs that meet the repetition threshold and assigns stable IDs
func finalizeBlobIDs(idx map[string]*BlobDef) (map[string]*BlobDef, map[string]*BlobDef) {
	blobsByID := make(map[string]*BlobDef)
	blobsByHash := make(map[string]*BlobDef)
	for hash, def := range idx {
		if def.Count >= 2 && len(def.Content) >= largeBlobThresholdBytes {
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
func compressRepeatedBlocks(s string) (string, bool) {
	lines := strings.Split(s, "\n")
	if len(lines) == 0 {
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
			w.WriteString(fmt.Sprintf("- content:\n%s\n(unreadable: %s)\n%s\n", delimiter, entry.ReadError, delimiter))
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
			if replaced, changed := replaceLargeBlobs(contentStr, compCtx); changed {
				contentStr = replaced
				compCtx.Applied = true
			}
			if compressed, changed := compressRepeatedBlocks(contentStr); changed {
				contentStr = compressed
				compCtx.Applied = true
			}
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

		if tcountDetailed {
			tcount = true
		}
		if tcount && dryRun {
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
		if tcountDetailed {
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
			printFinalOutput(output.String(), prefixMessage, suffixMessage)
			return nil
		}

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
		if compressOutput {
			// build global index for large repeated blobs across files and command outputs
			tempIdx := make(map[string]*BlobDef)
			buildLargeBlobIndex(root, tempIdx)
			// include command outputs in the blob index
			for _, r := range cmdResults {
				for _, block := range extractLargeParagraphs(r.Stdout, largeBlobThresholdBytes) {
					h := calculateFileHash([]byte(block))
					if existing, ok := tempIdx[h]; ok {
						existing.Count++
					} else {
						tempIdx[h] = &BlobDef{ID: "", Hash: h, Content: block, Count: 1}
					}
				}
				for _, block := range extractLargeParagraphs(r.Stderr, largeBlobThresholdBytes) {
					h := calculateFileHash([]byte(block))
					if existing, ok := tempIdx[h]; ok {
						existing.Count++
					} else {
						tempIdx[h] = &BlobDef{ID: "", Hash: h, Content: block, Count: 1}
					}
				}
			}
			blobsByID, blobsByHash := finalizeBlobIDs(tempIdx)
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
			compCtx = &CompressionContext{
				Enabled:     true,
				BlobsByID:   blobsByID,
				BlobsByHash: blobsByHash,
				BlobIDs:     blobIDs,
				UsedBlobIDs: make(map[string]bool),
			}
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
						if replaced, changed := replaceLargeBlobs(stdoutStr, compCtx); changed {
							stdoutStr = replaced
							compCtx.Applied = true
						}
						if compressed, changed := compressRepeatedBlocks(stdoutStr); changed {
							stdoutStr = compressed
							compCtx.Applied = true
						}
					}
					output.WriteString(fmt.Sprintf("- stdout:\n%s\n%s\n%s\n", delimiter, stdoutStr, delimiter))
				} else {
					output.WriteString("- stdout: (empty)\n")
				}
				if r.Stderr != "" {
					stderrStr := r.Stderr
					if compCtx != nil && compCtx.Enabled {
						if replaced, changed := replaceLargeBlobs(stderrStr, compCtx); changed {
							stderrStr = replaced
							compCtx.Applied = true
						}
						if compressed, changed := compressRepeatedBlocks(stderrStr); changed {
							stderrStr = compressed
							compCtx.Applied = true
						}
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
		outputStr := output.String()
		finalStr := outputStr
		legendStr := ""
		blobsStr := ""
		var blobSections []OutputSection
		if compCtx != nil && compCtx.Applied {
			var legend strings.Builder
			legend.WriteString("Compression applied:\n")
			legend.WriteString("- Repeated lines/groups shown once + (...<<<repeats N times>>>...)\n")
			legend.WriteString("- Large repeated blobs replaced with <<<blob-id>>> and listed at end\n\n")
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
					blobsSection.WriteString(fmt.Sprintf("%s\n%s\n%s\n", delimiter, def.Content, delimiter))
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

		if tcount {
			model := tokensModel
			if strings.TrimSpace(tcountModel) != "" {
				model = tcountModel
			}
			tkm, err := tiktoken.EncodingForModel(model)
			if err != nil {
				return fmt.Errorf("failed to get tokenizer for model %q: %w", model, err)
			}

			printed := composeFinalOutput(finalStr, prefixMessage, suffixMessage)
			tokens := tkm.Encode(printed, nil, nil)
			totalTokens := len(tokens)

			fmt.Println(totalTokens)
			if !tcountDetailed {
				return nil
			}

			// Build sections for the fully printed output so we can attribute tokens.
			if sectionsPtr == nil {
				return fmt.Errorf("internal error: expected sections to be enabled for --tcount-detailed")
			}

			contentSections := sections
			if legendStr != "" {
				legendLen := len(legendStr)
				for i := range contentSections {
					contentSections[i].Start += legendLen
					contentSections[i].End += legendLen
				}
				contentSections = append([]OutputSection{{Label: "[legend]", Start: 0, End: legendLen}}, contentSections...)
			}
			if blobsStr != "" && len(blobSections) > 0 {
				shift := len(legendStr) + len(outputStr)
				for _, s := range blobSections {
					contentSections = append(contentSections, OutputSection{Label: s.Label, Start: s.Start + shift, End: s.End + shift})
				}
			}

			hasPrefix := strings.TrimSpace(prefixMessage) != ""
			hasSuffix := strings.TrimSpace(suffixMessage) != ""
			wrapper := "---\n"

			finalSections := make([]OutputSection, 0, len(contentSections)+4)
			offset := 0
			if hasPrefix {
				p := prefixMessage + "\n"
				finalSections = append(finalSections, OutputSection{Label: "[prefix]", Start: offset, End: offset + len(p)})
				offset += len(p)
			}
			if hasPrefix || hasSuffix {
				finalSections = append(finalSections, OutputSection{Label: "[wrapper]", Start: offset, End: offset + len(wrapper)})
				offset += len(wrapper)
			}
			for _, s := range contentSections {
				finalSections = append(finalSections, OutputSection{Label: s.Label, Start: s.Start + offset, End: s.End + offset})
			}
			offset += len(finalStr)
			if hasPrefix || hasSuffix {
				finalSections = append(finalSections, OutputSection{Label: "[wrapper]", Start: offset, End: offset + len(wrapper)})
				offset += len(wrapper)
			}
			if hasSuffix {
				s := suffixMessage + "\n"
				finalSections = append(finalSections, OutputSection{Label: "[suffix]", Start: offset, End: offset + len(s)})
				offset += len(s)
			}

			if offset != len(printed) {
				// Keep going; token counts will be best-effort.
			}

			finalSections = fillSectionGaps(finalSections, len(printed))
			totalTokens, countsByLabel := tokenCountsBySection(tkm, tokens, finalSections)

			filePaths := make(map[string]bool)
			dirPaths := make(map[string]bool)
			collectNodePaths(root, filePaths, dirPaths)

			subtreeTokens := make(map[string]int, len(filePaths)+len(dirPaths))
			subtreeFiles := make(map[string]int, len(filePaths)+len(dirPaths))
			computeSubtreeTokenStats(root, countsByLabel, subtreeTokens, subtreeFiles)

			pathTokens := subtreeTokens[root.Path]
			nonPathTokens := totalTokens - pathTokens

			fmt.Printf("\nmodel: %s\n", model)
			fmt.Printf("path tokens: %d\n", pathTokens)
			fmt.Printf("non-path tokens: %d\n", nonPathTokens)

			type item struct {
				Label  string
				Path   string
				Tokens int
				Files  int
				IsDir  bool
			}

			sortItems := func(items []item) {
				sort.Slice(items, func(i, j int) bool {
					if items[i].Tokens == items[j].Tokens {
						return items[i].Label < items[j].Label
					}
					return items[i].Tokens > items[j].Tokens
				})
			}

			const maxTopLevelLines = 20
			topLevel := make([]item, 0, len(root.Children))
			for _, child := range root.Children {
				tok := subtreeTokens[child.Path]
				if tok == 0 {
					continue
				}
				label := child.Path
				if child.IsDir {
					label = formatDirPathForReport(child.Path)
				}
				topLevel = append(topLevel, item{
					Label:  label,
					Path:   child.Path,
					Tokens: tok,
					Files:  subtreeFiles[child.Path],
					IsDir:  child.IsDir,
				})
			}
			sortItems(topLevel)

			fmt.Printf("\ntop-level (by path tokens):\n")
			topLevelLimit := maxTopLevelLines
			if len(topLevel) < topLevelLimit {
				topLevelLimit = len(topLevel)
			}
			for i := 0; i < topLevelLimit; i++ {
				if topLevel[i].IsDir {
					fmt.Printf("%d\t%s\t(%s, %d files)\n", topLevel[i].Tokens, topLevel[i].Label, formatPercent(topLevel[i].Tokens, pathTokens), topLevel[i].Files)
					continue
				}
				fmt.Printf("%d\t%s\t(%s)\n", topLevel[i].Tokens, topLevel[i].Label, formatPercent(topLevel[i].Tokens, pathTokens))
			}
			if len(topLevel) > topLevelLimit {
				fmt.Printf("...\n")
			}

			fmt.Printf("\ndominant path:\n")
			current := root
			for depth := 0; depth < 8; depth++ {
				var best *FileEntry
				bestTokens := 0
				for _, child := range current.Children {
					tok := subtreeTokens[child.Path]
					if tok > bestTokens {
						bestTokens = tok
						best = child
					}
				}
				if best == nil || bestTokens == 0 {
					break
				}
				label := best.Path
				if best.IsDir {
					label = formatDirPathForReport(best.Path)
					fmt.Printf("%d\t%s\t(%s, %d files)\n", bestTokens, label, formatPercent(bestTokens, pathTokens), subtreeFiles[best.Path])
					current = best
					continue
				}
				fmt.Printf("%d\t%s\t(%s)\n", bestTokens, label, formatPercent(bestTokens, pathTokens))
				break
			}

			const maxDirLines = 20
			dirs := make([]item, 0, len(dirPaths))
			for dir := range dirPaths {
				if dir == root.Path {
					continue
				}
				tok := subtreeTokens[dir]
				if tok == 0 {
					continue
				}
				dirs = append(dirs, item{
					Label:  formatDirPathForReport(dir),
					Path:   dir,
					Tokens: tok,
					Files:  subtreeFiles[dir],
					IsDir:  true,
				})
			}
			sortItems(dirs)

			fmt.Printf("\ntop directories (subtree):\n")
			dirLimit := maxDirLines
			if len(dirs) < dirLimit {
				dirLimit = len(dirs)
			}
			for i := 0; i < dirLimit; i++ {
				fmt.Printf("%d\t%s\t(%s, %d files)\n", dirs[i].Tokens, dirs[i].Label, formatPercent(dirs[i].Tokens, pathTokens), dirs[i].Files)
			}
			if len(dirs) > dirLimit {
				fmt.Printf("...\n")
			}

			const maxFileLines = 20
			files := make([]item, 0, len(filePaths))
			for fp := range filePaths {
				tok := subtreeTokens[fp]
				if tok == 0 {
					continue
				}
				files = append(files, item{
					Label:  fp,
					Path:   fp,
					Tokens: tok,
					Files:  1,
					IsDir:  false,
				})
			}
			sortItems(files)

			fmt.Printf("\ntop files:\n")
			fileLimit := maxFileLines
			if len(files) < fileLimit {
				fileLimit = len(files)
			}
			for i := 0; i < fileLimit; i++ {
				fmt.Printf("%d\t%s\t(%s)\n", files[i].Tokens, files[i].Label, formatPercent(files[i].Tokens, pathTokens))
			}
			if len(files) > fileLimit {
				fmt.Printf("...\n")
			}

			const maxOtherLines = 15
			others := make([]item, 0, len(countsByLabel))
			for label, n := range countsByLabel {
				if n == 0 {
					continue
				}
				if filePaths[label] || dirPaths[label] {
					continue
				}
				others = append(others, item{Label: label, Path: label, Tokens: n})
			}
			sortItems(others)

			if len(others) > 0 {
				fmt.Printf("\nother sections:\n")
				otherLimit := maxOtherLines
				if len(others) < otherLimit {
					otherLimit = len(others)
				}
				for i := 0; i < otherLimit; i++ {
					fmt.Printf("%d\t%s\n", others[i].Tokens, others[i].Label)
				}
				if len(others) > otherLimit {
					fmt.Printf("...\n")
				}
			}
			return nil
		}

		printFinalOutput(finalStr, prefixMessage, suffixMessage)
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
	rootCmd.Flags().BoolVarP(&showTotalSize, "show-total-size", "Z", false, "Show total size of all files")

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

	// Output compression flag (disabled by default)
	rootCmd.Flags().BoolVar(&compressOutput, "compress", false, "Compress output by collapsing repeats and extracting large repeated blobs")

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
