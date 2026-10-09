// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package local

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

func TestLinuxInterceptReadinessPeer(t *testing.T) {
	if os.Getenv("LOCAL_READINESS_PEER") != "1" {
		return
	}
	if err := runLinuxReadinessPeer(os.Getenv("LOCAL_READINESS_DIR")); err != nil {
		t.Fatal(err)
	}
}

// This unprivileged peer gates native-protocol receive and rule application in a
// separate process. Its real TCP origin reports the state at socket acceptance;
// it models startup ordering, not privileged eBPF interception.
func runLinuxReadinessPeer(dir string) error {
	peer, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: filepath.Join(dir, "redirector"), Net: "unixgram"})
	if err != nil {
		return err
	}
	defer func() { _ = peer.Close() }()
	origin, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	var applied atomic.Bool
	var workers sync.WaitGroup
	defer workers.Wait()
	defer func() { _ = origin.Close() }()
	workers.Go(func() {
		for {
			conn, err := origin.Accept()
			if err != nil {
				return
			}
			response := "bypass"
			if applied.Load() {
				response = "intercept"
			}
			_, _ = io.WriteString(conn, response)
			_ = conn.Close()
		}
	})
	events := os.NewFile(3, "readiness-events")
	defer func() { _ = events.Close() }()
	if _, err := fmt.Fprintln(events, origin.Addr()); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(os.Stdout, filepath.Join(dir, "redirector")); err != nil {
		return err
	}
	commands := bufio.NewScanner(os.Stdin)
	buf := make([]byte, maxNativeIPCMessageSize)
	var first []byte
	for commands.Scan() {
		command := commands.Text()
		if command == "exit" {
			return nil
		}
		if command == "apply" {
			applied.Store(true)
		} else {
			n, _, err := peer.ReadFromUnix(buf)
			if err != nil {
				return err
			}
			if command == "shutdown" {
				if n != 0 {
					return fmt.Errorf("unexpected extra native frame: %d bytes", n)
				}
				return nil
			}
			var message FromProxy
			if err := proto.Unmarshal(buf[:n], &message); err != nil {
				return err
			}
			switch command {
			case "first":
				want, err := EncodeInterceptSpec("curl", uint32(os.Getppid()))
				if err != nil || !proto.Equal(message.GetInterceptConf(), want) {
					return fmt.Errorf("first config = %v, want %v: %w", message.GetInterceptConf(), want, err)
				}
				first = bytes.Clone(buf[:n])
			case "barrier":
				if !bytes.Equal(first, buf[:n]) {
					return errors.New("config barrier differs from first frame")
				}
			case "packet":
				if got := string(message.GetPacket().GetData()); got != "end of configs" {
					return fmt.Errorf("unexpected third config or packet: %q", got)
				}
			default:
				return fmt.Errorf("unexpected fixture command %q", command)
			}
		}
		if _, err := fmt.Fprintln(events, command); err != nil {
			return err
		}
	}
	return commands.Err()
}

func linuxReadinessFixture(t *testing.T) (*linuxRedirector, io.WriteCloser, *bufio.Scanner, string) {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	r := NewLinuxRedirector(t.TempDir(), binary).(*linuxRedirector)
	var commands io.WriteCloser
	var events *os.File
	r.start = func(ctx context.Context, _, dir string) (*exec.Cmd, io.ReadCloser, error) {
		read, write, err := os.Pipe()
		if err != nil {
			return nil, nil, err
		}
		events = read
		cmd := exec.CommandContext(ctx, binary, "-test.run=^TestLinuxInterceptReadinessPeer$")
		cmd.Env = append(os.Environ(), "LOCAL_READINESS_PEER=1", "LOCAL_READINESS_DIR="+dir)
		cmd.ExtraFiles = []*os.File{write}
		cmd.Stderr = os.Stderr
		commands, err = cmd.StdinPipe()
		if err != nil {
			_ = read.Close()
			_ = write.Close()
			return nil, nil, err
		}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			_ = commands.Close()
			_ = read.Close()
			_ = write.Close()
			return nil, nil, err
		}
		err = cmd.Start()
		_ = write.Close()
		if err != nil {
			_ = stdout.Close()
			_ = commands.Close()
			_ = read.Close()
			return nil, nil, err
		}
		return cmd, stdout, nil
	}
	t.Cleanup(func() {
		if commands != nil {
			_, _ = io.WriteString(commands, "exit\n")
			_ = commands.Close()
		}
		if err := r.Close(); err != nil {
			t.Error(err)
		}
		if events != nil {
			_ = events.Close()
		}
	})
	if err := r.Launch(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := events.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(events)
	if !scanner.Scan() {
		t.Fatalf("missing origin address: %v", scanner.Err())
	}
	return r, commands, scanner, scanner.Text()
}

func linuxReadinessQueued(t *testing.T, r *linuxRedirector) int {
	t.Helper()
	raw, err := r.conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var queued int
	var queueErr error
	err = raw.Control(func(fd uintptr) { queued, queueErr = unix.IoctlGetInt(int(fd), unix.TIOCOUTQ) })
	if err := errors.Join(err, queueErr); err != nil {
		t.Fatal(err)
	}
	return queued
}

func TestLinuxInterceptReadiness(t *testing.T) {
	tests := map[string]struct{ stage string }{
		"success: socket creation waits for applied config and identical barrier": {stage: "ready"},
		"error: cancellation before native receive fails closed":                  {stage: "cancel"},
		"error: native exit before receive never reports ready":                   {stage: "exit"},
		"error: deadline before native receive fails closed":                      {stage: "deadline"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			r, commands, events, address := linuxReadinessFixture(t)
			command := func(text string) {
				t.Helper()
				if _, err := io.WriteString(commands, text+"\n"); err != nil {
					t.Fatal(err)
				}
			}
			ack := func(want string) {
				t.Helper()
				if !events.Scan() {
					t.Fatalf("missing %q acknowledgment: %v", want, events.Err())
				}
				if diff := gocmp.Diff(want, events.Text()); diff != "" {
					t.Fatalf("peer stage (-want +got):\n%s", diff)
				}
			}
			probe := func() (string, error) {
				conn, err := net.DialTimeout("tcp4", address, 5*time.Second)
				if err != nil {
					return "", err
				}
				defer func() { _ = conn.Close() }()
				if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
					return "", err
				}
				data, err := io.ReadAll(conn)
				return string(data), err
			}
			ctx, cancel := context.WithCancel(t.Context())
			if tt.stage == "deadline" {
				cancel()
				ctx, cancel = context.WithTimeout(t.Context(), 100*time.Millisecond)
			}
			defer cancel()
			type result struct {
				state string
				err   error
			}
			results := make(chan result, 1)
			var workers sync.WaitGroup
			workers.Go(func() {
				err := r.SetIntercept(ctx, "curl")
				var state string
				if err == nil {
					state, err = probe()
				}
				results <- result{state: state, err: err}
			})
			t.Cleanup(func() {
				cancel()
				_, _ = io.WriteString(commands, "exit\n")
				_ = commands.Close()
				_ = r.Close()
				workers.Wait()
			})
			ticker := time.NewTicker(time.Millisecond)
			defer ticker.Stop()
			deadline := time.NewTimer(30 * time.Second)
			defer deadline.Stop()
			for linuxReadinessQueued(t, r) == 0 {
				select {
				case <-ticker.C:
				case <-deadline.C:
					t.Fatal("configuration never reached the real native queue")
				}
			}
			if tt.stage == "ready" {
				if state, err := probe(); state != "bypass" || err != nil {
					t.Fatalf("socket before native apply = %q, %v; want bypass", state, err)
				}
				command("first")
				ack("first")
				for linuxReadinessQueued(t, r) == 0 {
					select {
					case got := <-results:
						t.Fatalf("reported ready before rule application/barrier: client=%q, err=%v", got.state, got.err)
					case <-ticker.C:
					case <-deadline.C:
						t.Fatal("second configuration barrier was never queued")
					}
				}
				command("apply")
				ack("apply")
				select {
				case got := <-results:
					t.Fatalf("reported ready before barrier receive: %+v", got)
				default:
				}
				command("barrier")
				ack("barrier")
			} else {
				switch tt.stage {
				case "cancel":
					cancel()
				case "deadline":
					<-ctx.Done()
				}
				command("exit")
			}
			var got result
			select {
			case got = <-results:
			case <-deadline.C:
				t.Fatal("readiness did not finish after native progression or exit")
			}
			if tt.stage != "ready" {
				want := context.Canceled
				switch tt.stage {
				case "exit":
					want = net.ErrClosed
				case "deadline":
					want = context.DeadlineExceeded
				}
				if !errors.Is(got.err, want) {
					t.Fatalf("readiness error = %v, want %v; client=%q", got.err, want, got.state)
				}
				if _, err := r.channel(); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("failed readiness left daemon active: %v", err)
				}
				return
			}
			if got.err != nil || gocmp.Diff("intercept", got.state) != "" {
				t.Fatalf("socket after readiness = %q, %v; want intercept", got.state, got.err)
			}
			if err := r.WritePacket(t.Context(), &Packet{Data: []byte("end of configs")}); err != nil {
				t.Fatal(err)
			}
			command("packet")
			ack("packet")
			command("shutdown")
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
