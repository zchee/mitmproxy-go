// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"

	"github.com/zchee/mitmproxy-go/internal/local"
	"github.com/zchee/mitmproxy-go/internal/proxy/modespec"
)

func localIPCRead(t *testing.T, peer net.Conn, message proto.Message) {
	t.Helper()
	var prefix [4]byte
	if _, err := io.ReadFull(peer, prefix[:]); err != nil {
		t.Fatal(err)
	}
	length := binary.BigEndian.Uint32(prefix[:])
	if length > 8<<20 {
		t.Fatalf("IPC message length = %d", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(peer, payload); err != nil {
		t.Fatal(err)
	}
	if err := proto.Unmarshal(payload, message); err != nil {
		t.Fatal(err)
	}
}

// The launcher signals a real FIFO only after the landed redirector has bound
// its Unix listener. This tests IPC without installing a system extension.
func localIPCFixture(t *testing.T) (local.Redirector, *net.UnixConn) {
	t.Helper()
	root := t.TempDir()
	fifo := filepath.Join(root, "ready")
	if output, err := exec.CommandContext(t.Context(), "mkfifo", fifo).CombinedOutput(); err != nil {
		t.Fatalf("mkfifo: %v, %s", err, output)
	}
	ready, err := os.OpenFile(fifo, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ready.Close() })
	starter := filepath.Join(root, "starter")
	if err := os.WriteFile(starter, []byte("#!/bin/sh\nprintf x > "+strconv.Quote(fifo)+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	redirector := local.NewMacOSRedirector(root, starter)
	t.Cleanup(func() { _ = redirector.Close() })
	launched := make(chan error, 1)
	go func() { launched <- redirector.Launch(t.Context()) }()
	signaled := make(chan error, 1)
	go func() { var b [1]byte; _, err := io.ReadFull(ready, b[:]); signaled <- err }()
	select {
	case err := <-signaled:
		if err != nil {
			t.Fatal(err)
		}
	case err := <-launched:
		t.Fatalf("daemon launch ended before readiness: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("native IPC readiness hang detector")
	}
	peer, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: "/tmp/mitmproxy-" + strconv.Itoa(os.Getpid()), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	if err := <-launched; err != nil {
		t.Fatal(err)
	}
	if err := peer.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return redirector, peer
}

func localIPCMode(t *testing.T, cfg Config, redirector local.Redirector, spec string) *Instance {
	t.Helper()
	// Keep the runtime regression compilable on the parent without this field.
	// The parent's actual mode admission, rather than compilation, must fail.
	field := reflect.ValueOf(&cfg).Elem().FieldByName("LocalRedirector")
	if field.IsValid() {
		field.Set(reflect.ValueOf(redirector))
	}
	mode, err := modespec.Parse(spec)
	if err != nil {
		t.Fatal(err)
	}
	instance, err := New(mode, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return instance
}

func TestLocalIPCSingleFrontend(t *testing.T) {
	if runtime.GOOS == "windows" {
		return
	}
	tests := map[string]struct{}{"current frontend reservation": {}}
	for name := range tests {
		t.Run(name, func(t *testing.T) {
			redirector, control := localIPCFixture(t)
			cfg, _, _ := fixture(t)
			first := localIPCMode(t, cfg, redirector, "local")
			second := localIPCMode(t, cfg, redirector, "local:curl")
			t.Cleanup(func() { _ = first.Stop(); _ = second.Stop() })
			if err := first.Start(t.Context()); err != nil {
				t.Fatal(err)
			}
			localIPCRead(t, control, new(local.InterceptConf))
			if err := second.Start(t.Context()); err == nil || err.Error() != "Cannot spawn more than one local redirector." {
				t.Fatalf("second frontend = %v", err)
			}
			if !first.IsRunning() || !second.IsRunning() {
				t.Fatal("local running state did not reflect current frontend")
			}
			if err := second.Stop(); err != nil {
				t.Fatal(err)
			}
			if !first.IsRunning() {
				t.Fatal("inactive frontend stopped the current source")
			}
			if err := first.Stop(); err != nil {
				t.Fatal(err)
			}
			localIPCRead(t, control, new(local.InterceptConf))
			if err := second.Start(t.Context()); err != nil {
				t.Fatal(err)
			}
			var configuration local.InterceptConf
			localIPCRead(t, control, &configuration)
			want := []string{"curl", "!" + strconv.Itoa(os.Getpid())}
			if diff := gocmp.Diff(want, configuration.Actions); diff != "" {
				t.Fatal(diff)
			}
			if err := second.Stop(); err != nil {
				t.Fatal(err)
			}
			localIPCRead(t, control, new(local.InterceptConf))
		})
	}
}

func TestLocalIPCDefaultAndDaemonReuse(t *testing.T) {
	if runtime.GOOS == "windows" {
		return
	}
	tests := map[string]struct {
		spec    string
		actions []string
	}{
		"blank mode excludes self once":         {spec: "local", actions: []string{"!" + strconv.Itoa(os.Getpid())}},
		"explicit rules retain final exclusion": {spec: "local:curl", actions: []string{"curl", "!" + strconv.Itoa(os.Getpid())}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			redirector, peer := localIPCFixture(t)
			cfg, _, _ := fixture(t)
			first := localIPCMode(t, cfg, redirector, tt.spec)
			t.Cleanup(func() { _ = first.Stop() })
			for range 2 {
				if err := first.Start(t.Context()); err != nil {
					t.Fatal(err)
				}
				if !first.IsRunning() || len(first.ListenAddrs()) != 0 {
					t.Fatal("local frontend did not become a no-port source")
				}
				var configuration local.InterceptConf
				localIPCRead(t, peer, &configuration)
				if diff := gocmp.Diff(tt.actions, configuration.Actions); diff != "" {
					t.Fatalf("rules (-want +got):\n%s", diff)
				}
				if err := first.Stop(); err != nil {
					t.Fatal(err)
				}
				localIPCRead(t, peer, &configuration)
				if len(configuration.Actions) != 0 || first.IsRunning() {
					t.Fatal("frontend Stop did not disable interception")
				}
				if err := redirector.Launch(t.Context()); err != nil {
					t.Fatalf("frontend Stop ended daemon: %v", err)
				}
			}
		})
	}
}
