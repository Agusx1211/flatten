package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/pkoukk/tiktoken-go"
)

func buildTokenReport(printed string, model string, detailed bool, sections []OutputSection, sectionsEnabled bool, legendStr string, outputStr string, blobsStr string, blobSections []OutputSection, root *FileEntry, prefixMessage string, suffixMessage string) (string, error) {
	tkm, err := tiktoken.EncodingForModel(model)
	if err != nil {
		return "", fmt.Errorf("failed to get tokenizer for model %q: %w", model, err)
	}

	tokens := tkm.Encode(printed, nil, nil)
	totalTokens := len(tokens)

	var b strings.Builder
	fmt.Fprintf(&b, "%d\n", totalTokens)
	if !detailed {
		return b.String(), nil
	}
	if !sectionsEnabled {
		return "", fmt.Errorf("internal error: expected sections to be enabled for --tcount-detailed")
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
	finalContentLen := len(legendStr) + len(outputStr) + len(blobsStr)
	offset += finalContentLen
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

	fmt.Fprintf(&b, "\nmodel: %s\n", model)
	fmt.Fprintf(&b, "path tokens: %d\n", pathTokens)
	fmt.Fprintf(&b, "non-path tokens: %d\n", nonPathTokens)

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

	fmt.Fprintf(&b, "\ntop-level (by path tokens):\n")
	topLevelLimit := maxTopLevelLines
	if len(topLevel) < topLevelLimit {
		topLevelLimit = len(topLevel)
	}
	for i := 0; i < topLevelLimit; i++ {
		if topLevel[i].IsDir {
			fmt.Fprintf(&b, "%d\t%s\t(%s, %d files)\n", topLevel[i].Tokens, topLevel[i].Label, formatPercent(topLevel[i].Tokens, pathTokens), topLevel[i].Files)
			continue
		}
		fmt.Fprintf(&b, "%d\t%s\t(%s)\n", topLevel[i].Tokens, topLevel[i].Label, formatPercent(topLevel[i].Tokens, pathTokens))
	}
	if len(topLevel) > topLevelLimit {
		fmt.Fprintf(&b, "...\n")
	}

	fmt.Fprintf(&b, "\ndominant path:\n")
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
			fmt.Fprintf(&b, "%d\t%s\t(%s, %d files)\n", bestTokens, label, formatPercent(bestTokens, pathTokens), subtreeFiles[best.Path])
			current = best
			continue
		}
		fmt.Fprintf(&b, "%d\t%s\t(%s)\n", bestTokens, label, formatPercent(bestTokens, pathTokens))
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

	fmt.Fprintf(&b, "\ntop directories (subtree):\n")
	dirLimit := maxDirLines
	if len(dirs) < dirLimit {
		dirLimit = len(dirs)
	}
	for i := 0; i < dirLimit; i++ {
		fmt.Fprintf(&b, "%d\t%s\t(%s, %d files)\n", dirs[i].Tokens, dirs[i].Label, formatPercent(dirs[i].Tokens, pathTokens), dirs[i].Files)
	}
	if len(dirs) > dirLimit {
		fmt.Fprintf(&b, "...\n")
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

	fmt.Fprintf(&b, "\ntop files:\n")
	fileLimit := maxFileLines
	if len(files) < fileLimit {
		fileLimit = len(files)
	}
	for i := 0; i < fileLimit; i++ {
		fmt.Fprintf(&b, "%d\t%s\t(%s)\n", files[i].Tokens, files[i].Label, formatPercent(files[i].Tokens, pathTokens))
	}
	if len(files) > fileLimit {
		fmt.Fprintf(&b, "...\n")
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
		fmt.Fprintf(&b, "\nother sections:\n")
		otherLimit := maxOtherLines
		if len(others) < otherLimit {
			otherLimit = len(others)
		}
		for i := 0; i < otherLimit; i++ {
			fmt.Fprintf(&b, "%d\t%s\n", others[i].Tokens, others[i].Label)
		}
		if len(others) > otherLimit {
			fmt.Fprintf(&b, "...\n")
		}
	}
	return b.String(), nil
}
