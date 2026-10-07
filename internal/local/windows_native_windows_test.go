// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package local

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"google.golang.org/protobuf/proto"
)

// This subprocess fixture exchanges synthetic messages without UAC or WinDivert.
func TestWindowsPipeFixture(t *testing.T) {
	name := os.Getenv("MITMPROXY_SYNTHETIC_PIPE")
	if name == "" {
		t.Skip("subprocess fixture is launched by the Windows contract cases")
	}
	path, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(path, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		t.Fatal(err)
	}
	mode := uint32(windows.PIPE_READMODE_MESSAGE)
	if err := windows.SetNamedPipeHandleState(handle, &mode, nil, nil); err != nil {
		_ = windows.CloseHandle(handle)
		t.Fatal(err)
	}
	pipe := &windowsMessagePipe{handle: handle}
	defer func() { _ = pipe.Close() }()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	for {
		buf := make([]byte, maxNativeIPCMessageSize+1)
		n, err := pipe.read(ctx, buf)
		if err != nil {
			return
		}
		var message FromProxy
		if err := proto.Unmarshal(buf[:n], &message); err != nil {
			t.Fatal(err)
		}
		if message.GetPacket() != nil {
			pid, name := uint32(123), "synthetic-windows-peer"
			packet := &PacketWithMeta{Data: message.GetPacket().GetData(), TunnelInfo: &TunnelInfo{Pid: &pid, ProcessName: &name}}
			wire, err := proto.Marshal(packet)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := pipe.write(ctx, wire); err != nil {
				return
			}
		}
	}
}

func syntheticWindowsLauncher(t *testing.T) func(context.Context, string, string) (windows.Handle, error) {
	t.Helper()
	return func(ctx context.Context, _, pipe string) (windows.Handle, error) {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		exe, err := os.Executable()
		if err != nil {
			return 0, err
		}
		// The controller owns child termination through its process handle.
		// A second context watcher could try to kill an already-exited child.
		cmd := exec.Command(exe, "-test.run=^TestWindowsPipeFixture$")
		cmd.Env = append(os.Environ(), "MITMPROXY_SYNTHETIC_PIPE="+pipe)
		if err := cmd.Start(); err != nil {
			return 0, err
		}
		handle, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_INFORMATION, false, uint32(cmd.Process.Pid))
		if err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return 0, err
		}
		result := make(chan error, 1)
		go func() { result <- cmd.Wait() }()
		t.Cleanup(func() {
			if err := <-result; err != nil {
				t.Error(err)
			}
		})
		return handle, nil
	}
}

func TestWindowsNative(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		size            int
		cancelAfterExit bool
	}{
		"success: message boundaries and metadata":     {size: 37},
		"success: maximum packet message":              {size: maxNativePacketSize},
		"success: cancellation after owned child exit": {size: 1, cancelAfterExit: true},
	}
	index := 0
	for name, test := range tests {
		index++
		t.Run(name, func(t *testing.T) {
			r := NewWindowsRedirector(t.TempDir(), exe).(*windowsRedirector)
			r.pipeName += "-synthetic-" + strconv.Itoa(index)
			r.start = syntheticWindowsLauncher(t)
			t.Cleanup(func() { _ = r.Close() })
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			if err := r.Launch(ctx); err != nil {
				t.Fatal(err)
			}
			for _, spec := range []string{"curl", ""} {
				if err := r.SetIntercept(ctx, spec); err != nil {
					t.Fatal(err)
				}
			}
			data := make([]byte, test.size)
			if err := r.WritePacket(ctx, &Packet{Data: data}); err != nil {
				t.Fatal(err)
			}
			packet, err := r.ReadPacket(ctx)
			if err != nil || len(packet.GetData()) != test.size || packet.GetTunnelInfo().GetPid() != 123 {
				t.Fatalf("native message = %v, %v", packet, err)
			}
			readCtx, stop := context.WithTimeout(ctx, 20*time.Millisecond)
			defer stop()
			if _, err := r.ReadPacket(readCtx); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("canceled native read = %v", err)
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			if test.cancelAfterExit {
				select {
				case <-r.processDone:
				default:
					t.Fatal("Close returned before the owned child exited")
				}
				cancel()
			}
			if err := r.WritePacket(t.Context(), &Packet{Data: []byte("late")}); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("packet write after Close = %v", err)
			}
		})
	}
}

func TestWindowsShellABI(t *testing.T) {
	want := uintptr(112)
	if unsafe.Sizeof(uintptr(0)) == 4 {
		want = 60
	}
	if got := unsafe.Sizeof(shellExecuteInfo{}); got != want {
		t.Fatalf("SHELLEXECUTEINFOW size = %d, want %d", got, want)
	}
}
