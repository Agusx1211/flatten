//go:build unix

package main

import (
	"fmt"
	"os"
	"os/user"
	"strings"
	"syscall"
)

// getOwnershipInfo returns ownership information for Unix-like systems
func getOwnershipInfo(path string, w *strings.Builder) {
	info, err := os.Stat(path)
	if err != nil {
		return
	}

	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		if owner, err := user.LookupId(fmt.Sprint(stat.Uid)); err == nil {
			w.WriteString(fmt.Sprintf("- owner: %s\n", owner.Username))
		}
		if group, err := user.LookupGroupId(fmt.Sprint(stat.Gid)); err == nil {
			w.WriteString(fmt.Sprintf("- group: %s\n", group.Name))
		}
	}
}
