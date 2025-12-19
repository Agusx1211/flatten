package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

func runClipboardCommand(name string, args []string, data string, stdout io.Writer) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(data)
	if stdout != nil {
		cmd.Stdout = stdout
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return fmt.Errorf("%s failed: %s", name, msg)
		}
		return fmt.Errorf("%s failed: %w", name, err)
	}
	return nil
}

func copyToClipboard(data string) error {
	switch runtime.GOOS {
	case "darwin":
		if _, err := exec.LookPath("pbcopy"); err != nil {
			return fmt.Errorf("pbcopy not found in PATH")
		}
		return runClipboardCommand("pbcopy", nil, data, io.Discard)
	case "windows":
		if _, err := exec.LookPath("clip"); err != nil {
			return fmt.Errorf("clip not found in PATH")
		}
		return runClipboardCommand("clip", nil, data, io.Discard)
	default:
		if path, _ := exec.LookPath("wl-copy"); path != "" {
			return runClipboardCommand(path, nil, data, io.Discard)
		}
		if path, _ := exec.LookPath("xclip"); path != "" {
			return runClipboardCommand(path, []string{"-selection", "clipboard"}, data, io.Discard)
		}
		if path, _ := exec.LookPath("xsel"); path != "" {
			return runClipboardCommand(path, []string{"--clipboard", "--input"}, data, io.Discard)
		}
		if path, _ := exec.LookPath("clip.exe"); path != "" {
			return runClipboardCommand(path, nil, data, io.Discard)
		}
		return fmt.Errorf("no clipboard utility found (tried wl-copy, xclip, xsel, clip.exe)")
	}
}

func osc52Sequence(data string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(data))
	seq := fmt.Sprintf("\x1b]52;c;%s\x07", encoded)
	if os.Getenv("TMUX") != "" {
		return "\x1bPtmux;" + seq + "\x1b\\"
	}
	if strings.HasPrefix(os.Getenv("TERM"), "screen") {
		return "\x1bP" + seq + "\x1b\\"
	}
	return seq
}

func copyToOSC52(data string) error {
	if _, err := io.WriteString(os.Stdout, osc52Sequence(data)); err != nil {
		return fmt.Errorf("failed to write OSC 52 sequence: %w", err)
	}
	return nil
}
