//go:build windows

package main

import (
	"strings"
)

// getOwnershipInfo returns ownership information for Windows systems
func getOwnershipInfo(path string, w *strings.Builder) {
	// On Windows, ownership information is not easily available
	w.WriteString("- owner: unavailable on this platform\n")
}
