// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package console

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/zchee/mitmproxy-go/options"
)

func TestMain(m *testing.M) {
	if scenario := os.Getenv("MITMPROXY_CONSOLE_LIFECYCLE_CASE"); scenario != "" {
		if err := consoleLifecycleChild(scenario); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func consoleLifecycleChild(scenario string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	opts := options.New()
	if err := opts.Update(ctx, map[string]any{"confdir": os.Getenv("MITMPROXY_CONSOLE_TEST_DIR"), "server": false, "listen_port": 0}); err != nil {
		return err
	}
	m, err := New(ctx, Config{Options: opts})
	if err != nil {
		return err
	}
	defer m.Close(context.WithoutCancel(ctx)) //nolint:errcheck // Explicit Close below retains its result.
	if _, err := m.NewProgram(); err != nil {
		return err
	}
	if _, err := m.NewModel(); err == nil {
		return errors.New("terminal owner allowed a second harness owner")
	}
	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	finished := make(chan error, 1)
	go func() { finished <- m.Run(runCtx) }()
	select {
	case <-m.Ready():
		switch scenario {
		case "shutdown":
			process, err := os.FindProcess(os.Getpid())
			if err != nil {
				return err
			}
			tick := time.NewTicker(time.Millisecond)
			defer tick.Stop()
			var sequence uint64
			for range 2 {
				if err := process.Signal(syscall.SIGINT); err != nil {
					return err
				}
				for {
					confirmed := false
					var current uint64
					if err := m.Do(ctx, func(context.Context) error {
						state := m.Bridge.Control.State()
						current = m.Bridge.Control.sequence
						confirmed = state.Prompt == "confirm" && state.Text == "Quit" && current > sequence
						return nil
					}); err != nil {
						return err
					}
					data, err := os.ReadFile(os.Getenv("MITMPROXY_CONSOLE_TEST_TRANSCRIPT"))
					if err != nil && !errors.Is(err, os.ErrNotExist) {
						return err
					}
					text := ansi.Strip(string(data))
					if confirmed && strings.Contains(text, "Quit") && strings.Contains(text, "Yes") && strings.Contains(text, "No") {
						sequence = current
						break
					}
					select {
					case err := <-finished:
						return fmt.Errorf("interrupt exited before confirmation: %w", err)
					case <-ctx.Done():
						return ctx.Err()
					case <-tick.C:
					}
				}
			}
			if _, err := fmt.Fprintln(os.Stdout, "console interrupt confirmation ready"); err != nil {
				return err
			}
		case "startup":
			process, err := os.FindProcess(os.Getpid())
			if err != nil {
				return err
			}
			if err := process.Signal(syscall.SIGTERM); err != nil {
				return err
			}
		case "reuse":
			cancelRun()
		default:
			m.Shutdown()
		}
	case err := <-finished:
		return fmt.Errorf("terminal exited before Init: %w", err)
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := <-finished; err != nil {
		return err
	}
	if err := m.Close(ctx); err != nil {
		return err
	}
	if err := m.Close(ctx); err != nil {
		return err
	}
	if scenario == "reuse" && m.Run(ctx) == nil {
		return errors.New("console master ran twice")
	}
	_, err = fmt.Fprintln(os.Stdout, "console lifecycle complete")
	return err
}

func TestConsoleMaster(t *testing.T) {
	t.Run("lifecycle", func(t *testing.T) {
		tests := map[string]struct{}{"startup": {}, "tty_refusal": {}, "utf8_warning": {}, "shutdown": {}, "constructor_cleanup": {}, "reuse": {}}
		for name := range tests {
			t.Run(name, func(t *testing.T) {
				if name == "constructor_cleanup" {
					ctx, cancel := context.WithCancel(t.Context())
					cancel()
					m, err := New(ctx, Config{Stdout: io.Discard, Stderr: io.Discard})
					if !errors.Is(err, context.Canceled) || m != nil {
						t.Fatalf("canceled constructor = %v, %v", m, err)
					}
					fresh, err := New(t.Context(), Config{Stdout: io.Discard, Stderr: io.Discard})
					mustConsole(t, err)
					mustConsole(t, fresh.Close(t.Context()))
					mustConsole(t, fresh.Close(t.Context()))
					fresh.Bridge.DrainTo(func(tea.Msg) { t.Error("snapshot delivery ran after close") })()
					fresh.Bridge.DeliverEffectsTo(func(tea.Msg) { t.Error("effect delivery ran after close") })()
					if fresh.Bridge.started.Load() || fresh.Bridge.deliveryStarted.Load() {
						t.Fatal("a queued frontend runner started after Close joined its lifetime")
					}
					return
				}
				if name == "tty_refusal" {
					var output bytes.Buffer
					m, err := New(t.Context(), Config{Stdout: &output, Stderr: io.Discard})
					mustConsole(t, err)
					_, err = m.NewProgram()
					mustConsole(t, err)
					err = m.Run(t.Context())
					if err == nil || !strings.Contains(err.Error(), "Please run mitmproxy in an interactive shell environment.") {
						t.Fatalf("TTY refusal: %v", err)
					}
					if m.uiStarted.Load() || len(m.ProxyServer.ListenAddrs()) != 0 {
						t.Fatal("non-TTY refusal started terminal or listener work")
					}
					mustConsole(t, m.Close(t.Context()))
					return
				}
				if name == "reuse" {
					m, err := New(t.Context(), Config{Stdout: io.Discard, Stderr: io.Discard})
					mustConsole(t, err)
					model, err := m.NewModel()
					mustConsole(t, err)
					if model.program != nil {
						t.Fatal("harness model is prebound to a terminal program")
					}
					if _, err := m.NewProgram(); err == nil {
						t.Fatal("harness owner allowed a second terminal owner")
					}
					mustConsole(t, m.Close(t.Context()))
				}
				if runtime.GOOS == "windows" {
					t.Fatal("native Windows terminal evidence is not enabled")
				}
				binary, err := os.Executable()
				mustConsole(t, err)
				script, err := exec.LookPath("script")
				mustConsole(t, err)
				directory := t.TempDir()
				transcript := filepath.Join(directory, "terminal.txt")
				args := []string{"-q", "-F", transcript, binary}
				if runtime.GOOS == "linux" {
					quoted := "'" + strings.ReplaceAll(binary, "'", "'\\''") + "'"
					args = []string{"-q", "-f", "-e", "-c", "exec " + quoted, transcript}
				}
				ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, script, args...) //nolint:gosec // The executable is the current controlled test binary.
				cmd.Env = append(os.Environ(), "MITMPROXY_CONSOLE_LIFECYCLE_CASE="+name, "MITMPROXY_CONSOLE_TEST_DIR="+directory, "MITMPROXY_CONSOLE_TEST_TRANSCRIPT="+transcript, "TERM=xterm-256color", "LC_ALL=en_US.UTF-8")
				if name == "utf8_warning" {
					cmd.Env = append(cmd.Env, "LC_ALL=C")
				}
				var inputDone chan error
				if name == "shutdown" {
					input, err := cmd.StdinPipe()
					mustConsole(t, err)
					defer input.Close() //nolint:errcheck // The child result and input write retain failures.
					inputDone = make(chan error, 1)
					go func() {
						tick := time.NewTicker(time.Millisecond)
						defer tick.Stop()
						for {
							data, err := os.ReadFile(transcript)
							if err != nil && !errors.Is(err, os.ErrNotExist) {
								inputDone <- err
								return
							}
							text := ansi.Strip(string(data))
							// console/master.py:70-81 offers Quit with yes/no one-key choices.
							if strings.Contains(text, "console interrupt confirmation ready") && strings.Contains(text, "Quit") && strings.Contains(text, "Yes") && strings.Contains(text, "No") {
								_, err := io.WriteString(input, "y")
								inputDone <- err
								return
							}
							select {
							case <-ctx.Done():
								inputDone <- ctx.Err()
								return
							case <-tick.C:
							}
						}
					}()
				}
				output, err := cmd.CombinedOutput()
				cancel()
				if inputDone != nil {
					if inputErr := <-inputDone; inputErr != nil {
						t.Fatalf("PTY confirmation input: %v\n%s", inputErr, output)
					}
				}
				if err != nil {
					t.Fatalf("real PTY lifecycle: %v\n%s", err, output)
				}
				if !bytes.Contains(output, []byte("console lifecycle complete")) {
					t.Fatalf("PTY child did not complete: %q", output)
				}
				if name == "utf8_warning" && !bytes.Contains(output, []byte("mitmproxy expects a UTF-8 console environment")) {
					t.Fatalf("missing locale warning: %q", output)
				}
				if name == "startup" && !bytes.Contains(output, []byte("\x1b[")) {
					t.Fatal("real terminal frontend emitted no control transcript")
				}
			})
		}
	})
}
