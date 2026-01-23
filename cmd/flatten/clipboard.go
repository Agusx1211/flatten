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

const osc52MaxSequence = 10000000

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

func osc52Sequence(data string) (string, error) {
	encoded := base64.StdEncoding.EncodeToString([]byte(data))
	if len(encoded) >= osc52MaxSequence {
		return "", fmt.Errorf("selection too long to send to terminal: %d limit, %d attempted", osc52MaxSequence, len(encoded))
	}
	seq := fmt.Sprintf("\x1b]52;c;%s\x07", encoded)
	if strings.HasPrefix(os.Getenv("TERM"), "screen") {
		if os.Getenv("TMUX") != "" {
			return tmuxDCS(seq), nil
		}
		return screenDCS(seq), nil
	}
	if strings.HasPrefix(os.Getenv("TERM"), "tmux") {
		return tmuxDCS(seq), nil
	}
	return seq, nil
}

func copyToOSC52(data string) error {
	if haveCodeServerClipboard() {
		if err := copyToCodeServerClipboard(data); err != nil {
			return err
		}
		return nil
	}
	seq, err := osc52Sequence(data)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(os.Stdout, seq); err != nil {
		return fmt.Errorf("failed to write OSC 52 sequence: %w", err)
	}
	return nil
}

func haveCodeServerClipboard() bool {
	if os.Getenv("VSCODE_IPC_HOOK_CLI") == "" && os.Getenv("TERM_PROGRAM") != "vscode" {
		return false
	}
	path, err := exec.LookPath("code-server")
	if err != nil {
		return false
	}
	out, err := exec.Command(path, "--help").CombinedOutput()
	if err != nil {
		return false
	}
	return bytes.Contains(out, []byte("--stdin-to-clipboard"))
}

func copyToCodeServerClipboard(data string) error {
	tmp, err := os.CreateTemp("", "osc52.")
	if err != nil {
		return fmt.Errorf("failed to create temp file for clipboard: %w", err)
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	if _, err := tmp.WriteString(data); err != nil {
		return fmt.Errorf("failed to buffer clipboard data: %w", err)
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to rewind clipboard buffer: %w", err)
	}

	cmd := exec.Command("code-server", "--stdin-to-clipboard")
	cmd.Stdin = tmp
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return fmt.Errorf("code-server --stdin-to-clipboard failed: %s", msg)
		}
		return fmt.Errorf("code-server --stdin-to-clipboard failed: %w", err)
	}
	return nil
}

func tmuxDCS(seq string) string {
	return "\x1bPtmux;\x1b" + seq + "\x1b\\"
}

func screenDCS(seq string) string {
	const limit = 256
	chunkSize := limit - 4
	if chunkSize <= 0 {
		return seq
	}
	var buf bytes.Buffer
	for len(seq) > 0 {
		if len(seq) < chunkSize {
			chunkSize = len(seq)
		}
		buf.WriteString("\x1bP")
		buf.WriteString(seq[:chunkSize])
		buf.WriteString("\x1b\\")
		seq = seq[chunkSize:]
	}
	return buf.String()
}
