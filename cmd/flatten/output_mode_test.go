package main

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestNormalizeOutputMode(t *testing.T) {
	cases := map[string]string{
		"print":    outputModePrint,
		"PRINT":    outputModePrint,
		"copy":     outputModeCopy,
		"ssh-copy": outputModeSSHCopy,
		"sshcopy":  outputModeSSHCopy,
		"ssh":      outputModeSSHCopy,
		"osc52":    outputModeSSHCopy,
		"shh-copy": outputModeSSHCopy,
	}
	for in, want := range cases {
		got, ok := normalizeOutputMode(in)
		if !ok {
			t.Fatalf("normalizeOutputMode(%q) returned ok=false", in)
		}
		if got != want {
			t.Fatalf("normalizeOutputMode(%q) = %q, want %q", in, got, want)
		}
	}
	if _, ok := normalizeOutputMode("bogus"); ok {
		t.Fatalf("normalizeOutputMode(bogus) should fail")
	}
}

func TestResolveOutputMode(t *testing.T) {
	mode, err := resolveOutputMode(outputModePrint, false, false, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mode != outputModePrint {
		t.Fatalf("expected default print, got %q", mode)
	}

	mode, err = resolveOutputMode(outputModeCopy, false, false, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mode != outputModeCopy {
		t.Fatalf("expected default copy, got %q", mode)
	}

	mode, err = resolveOutputMode(outputModeCopy, true, false, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mode != outputModePrint {
		t.Fatalf("expected explicit print, got %q", mode)
	}

	if _, err := resolveOutputMode(outputModePrint, true, true, false); err == nil {
		t.Fatalf("expected error for multiple output flags")
	}
}

func TestReadWriteDefaultOutputMode(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, flattenFileName)

	mode, err := readDefaultOutputModeFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mode != "" {
		t.Fatalf("expected empty mode for missing file, got %q", mode)
	}

	if err := writeDefaultOutputModeToFile(path, outputModeCopy); err != nil {
		t.Fatalf("unexpected error writing config: %v", err)
	}

	mode, err = readDefaultOutputModeFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error reading config: %v", err)
	}
	if mode != outputModeCopy {
		t.Fatalf("expected mode %q, got %q", outputModeCopy, mode)
	}

	cfg := map[string]any{
		"include": []string{"foo"},
		"exclude": []string{"bar"},
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("unexpected marshal error: %v", err)
	}
	if err := writeFile(path, data); err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}

	if err := writeDefaultOutputModeToFile(path, outputModeSSHCopy); err != nil {
		t.Fatalf("unexpected error updating config: %v", err)
	}

	mode, err = readDefaultOutputModeFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error reading config: %v", err)
	}
	if mode != outputModeSSHCopy {
		t.Fatalf("expected mode %q, got %q", outputModeSSHCopy, mode)
	}

	decoded := map[string]any{}
	if err := yaml.Unmarshal(mustReadFile(t, path), &decoded); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}
	if decoded["include"] == nil || decoded["exclude"] == nil {
		t.Fatalf("expected include/exclude to be preserved")
	}
}

func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o644)
}

func mustReadFile(t *testing.T, path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}
	return data
}
