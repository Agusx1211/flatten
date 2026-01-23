package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestHaveCodeServerClipboard(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("code-server stub uses a POSIX shell script")
	}

	t.Run("env-missing", func(t *testing.T) {
		dir := writeCodeServerStub(t, "--stdin-to-clipboard")
		t.Setenv("PATH", prependPath(dir))
		t.Setenv("VSCODE_IPC_HOOK_CLI", "")
		t.Setenv("TERM_PROGRAM", "")

		if haveCodeServerClipboard() {
			t.Fatalf("expected false when vscode env vars are missing")
		}
	})

	t.Run("help-missing-flag", func(t *testing.T) {
		dir := writeCodeServerStub(t, "Usage: code-server")
		t.Setenv("PATH", prependPath(dir))
		t.Setenv("VSCODE_IPC_HOOK_CLI", "1")
		t.Setenv("TERM_PROGRAM", "")

		if haveCodeServerClipboard() {
			t.Fatalf("expected false when flag is not advertised")
		}
	})

	t.Run("help-has-flag", func(t *testing.T) {
		dir := writeCodeServerStub(t, "Usage: code-server\n  --stdin-to-clipboard")
		t.Setenv("PATH", prependPath(dir))
		t.Setenv("VSCODE_IPC_HOOK_CLI", "1")
		t.Setenv("TERM_PROGRAM", "")

		if !haveCodeServerClipboard() {
			t.Fatalf("expected true when flag is advertised")
		}
	})
}

func writeCodeServerStub(t *testing.T, helpText string) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "code-server")
	script := "#!/bin/sh\n" +
		"if [ \"$1\" = \"--help\" ]; then\n" +
		"  cat <<'EOF'\n" + helpText + "\nEOF\n" +
		"  exit 0\n" +
		"fi\n" +
		"exit 0\n"

	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write stub: %v", err)
	}

	return dir
}

func prependPath(dir string) string {
	orig := os.Getenv("PATH")
	if orig == "" {
		return dir
	}
	return dir + string(os.PathListSeparator) + orig
}
