// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package vtcodes

import (
	"fmt"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// openPTYPair opens a pseudo-terminal master and its slave through
// /dev/ptmx, or skips the test where the device is unavailable.
func openPTYPair(t *testing.T) (master, slave *os.File) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("open /dev/ptmx: %v", err)
	}
	t.Cleanup(func() { _ = master.Close() })
	if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatalf("unlock pty slave: %v", err)
	}
	n, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatalf("read pty slave number: %v", err)
	}
	slave, err = os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatalf("open pty slave: %v", err)
	}
	t.Cleanup(func() { _ = slave.Close() })
	return master, slave
}

func TestEnsureSupportedTerminal(t *testing.T) {
	t.Parallel()
	master, slave := openPTYPair(t)
	if got := EnsureSupported(slave); !got {
		t.Fatalf("EnsureSupported(pty slave) = %v, want true", got)
	}
	if got := EnsureSupported(master); !got {
		t.Fatalf("EnsureSupported(pty master) = %v, want true", got)
	}
}

func TestColumnsTerminal(t *testing.T) {
	t.Parallel()
	master, slave := openPTYPair(t)
	ws := unix.Winsize{Row: 24, Col: 123}
	if err := unix.IoctlSetWinsize(int(master.Fd()), unix.TIOCSWINSZ, &ws); err != nil {
		t.Fatalf("set pty window size: %v", err)
	}
	n, ok := Columns(slave)
	if !ok || n != 123 {
		t.Fatalf("Columns(pty slave) = %d, %v, want 123, true", n, ok)
	}
}

func TestWidthFromZeroWidthTerminal(t *testing.T) {
	t.Parallel()
	_, slave := openPTYPair(t)
	// A fresh pseudo-terminal reports a 0x0 window; Python's
	// shutil.get_terminal_size falls back to 80 for a zero width.
	if got := widthFrom("", slave); got != 80 {
		t.Fatalf("widthFrom(%q, zero-width pty) = %d, want 80", "", got)
	}
}

func TestWidthFromTerminal(t *testing.T) {
	t.Parallel()
	master, slave := openPTYPair(t)
	ws := unix.Winsize{Row: 24, Col: 101}
	if err := unix.IoctlSetWinsize(int(master.Fd()), unix.TIOCSWINSZ, &ws); err != nil {
		t.Fatalf("set pty window size: %v", err)
	}
	tests := map[string]struct {
		env  string
		want int
	}{
		"success: terminal width used without COLUMNS": {env: "", want: 101},
		"success: COLUMNS overrides the terminal":      {env: "66", want: 66},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := widthFrom(tt.env, slave); got != tt.want {
				t.Fatalf("widthFrom(%q, pty slave) = %d, want %d", tt.env, got, tt.want)
			}
		})
	}
}
