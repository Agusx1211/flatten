package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	outputModePrint   = "print"
	outputModeCopy    = "copy"
	outputModeSSHCopy = "ssh-copy"
)

func normalizeOutputMode(mode string) (string, bool) {
	m := strings.TrimSpace(strings.ToLower(mode))
	switch m {
	case outputModePrint:
		return outputModePrint, true
	case outputModeCopy:
		return outputModeCopy, true
	case outputModeSSHCopy, "sshcopy", "ssh", "osc52", "shh-copy", "shhcopy", "shh":
		return outputModeSSHCopy, true
	default:
		return "", false
	}
}

func resolveOutputMode(defaultMode string, printFlag, copyFlag, sshFlag bool) (string, error) {
	selected := 0
	if printFlag {
		selected++
	}
	if copyFlag {
		selected++
	}
	if sshFlag {
		selected++
	}
	if selected > 1 {
		return "", fmt.Errorf("only one of --print, --copy, or --ssh-copy may be set")
	}
	if defaultMode == "" {
		defaultMode = outputModePrint
	}
	if printFlag {
		return outputModePrint, nil
	}
	if copyFlag {
		return outputModeCopy, nil
	}
	if sshFlag {
		return outputModeSSHCopy, nil
	}
	return defaultMode, nil
}

func readDefaultOutputModeFromFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return "", nil
	}
	var cfg map[string]any
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return "", fmt.Errorf("failed to parse %s: %w", path, err)
	}
	raw, ok := cfg["output"]
	if !ok {
		return "", nil
	}
	outputStr, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("invalid output value in %s: expected string", path)
	}
	normalized, ok := normalizeOutputMode(outputStr)
	if !ok {
		return "", fmt.Errorf("invalid output mode %q in %s (expected print, copy, or ssh-copy)", outputStr, path)
	}
	return normalized, nil
}

func defaultOutputConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, flattenFileName), nil
}

func readHomeDefaultOutputMode() (string, error) {
	path, err := defaultOutputConfigPath()
	if err != nil {
		return "", err
	}
	return readDefaultOutputModeFromFile(path)
}

func writeDefaultOutputModeToFile(path string, mode string) error {
	normalized, ok := normalizeOutputMode(mode)
	if !ok {
		return fmt.Errorf("invalid output mode %q (expected print, copy, or ssh-copy)", mode)
	}
	var cfg map[string]any
	data, err := os.ReadFile(path)
	if err == nil {
		if len(strings.TrimSpace(string(data))) > 0 {
			if err := yaml.Unmarshal(data, &cfg); err != nil {
				return fmt.Errorf("failed to parse %s: %w", path, err)
			}
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if cfg == nil {
		cfg = make(map[string]any)
	}
	cfg["output"] = normalized
	out, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to write %s: %w", path, err)
	}
	if len(out) == 0 || out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	perm := os.FileMode(0o644)
	if info, err := os.Stat(path); err == nil {
		perm = info.Mode().Perm()
	}
	return os.WriteFile(path, out, perm)
}

func writeHomeDefaultOutputMode(mode string) error {
	path, err := defaultOutputConfigPath()
	if err != nil {
		return err
	}
	return writeDefaultOutputModeToFile(path, mode)
}
