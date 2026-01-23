package main

import (
	"os"
	"strings"
	"testing"
)

func TestOSC52Sequence(t *testing.T) {
	data := "hello"
	encoded := "aGVsbG8="

	origTMUX := os.Getenv("TMUX")
	origTERM := os.Getenv("TERM")
	t.Cleanup(func() {
		os.Setenv("TMUX", origTMUX)
		os.Setenv("TERM", origTERM)
	})

	os.Setenv("TMUX", "")
	os.Setenv("TERM", "xterm-256color")
	seq, err := osc52Sequence(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(seq, "\x1b]52;c;"+encoded) || !strings.HasSuffix(seq, "\x07") {
		t.Fatalf("unexpected OSC52 sequence for xterm: %q", seq)
	}

	os.Setenv("TMUX", "1")
	os.Setenv("TERM", "screen-256color")
	seq, err = osc52Sequence(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantTmux := "\x1bPtmux;\x1b\x1b]52;c;" + encoded + "\x07\x1b\\"
	if seq != wantTmux {
		t.Fatalf("unexpected OSC52 sequence for tmux: %q", seq)
	}

	os.Setenv("TMUX", "")
	os.Setenv("TERM", "screen")
	seq, err = osc52Sequence(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantScreen := "\x1bP\x1b]52;c;" + encoded + "\x07\x1b\\"
	if seq != wantScreen {
		t.Fatalf("unexpected OSC52 sequence for screen: %q", seq)
	}
}
