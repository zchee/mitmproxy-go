// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package local

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type windowsRedirector struct {
	confdir, overridePath, pipeName string
	start                           func(context.Context, string, string) (windows.Handle, error)
	launchOnce, shutdownOnce        sync.Once
	processHandleOnce               sync.Once
	launchDone, closedCh            chan struct{}
	processDone                     chan struct{}
	readGate, writeGate             chan struct{}
	workers                         sync.WaitGroup
	mu                              sync.Mutex
	closed, ready                   bool
	pipe                            *windowsMessagePipe
	process                         windows.Handle
	cancelProcess                   context.CancelFunc
	launchErr, closeErr, processErr error
}

func newWindowsRedirector(confdir, overridePath string) Redirector {
	return &windowsRedirector{confdir: confdir, overridePath: overridePath, pipeName: `\\.\pipe\mitmproxy-transparent-proxy-` + strconv.Itoa(os.Getpid()), start: startWindowsRedirector, launchDone: make(chan struct{}), closedCh: make(chan struct{}), processDone: make(chan struct{}), readGate: make(chan struct{}, 1), writeGate: make(chan struct{}, 1)}
}

// This layout follows the SDK's SHELLEXECUTEINFOW, including pointer-sized
// handles and the icon/monitor union. Size assertions cover both Windows ABIs.
type shellExecuteInfo struct {
	size, mask                        uint32
	window                            windows.Handle
	verb, file, parameters, directory *uint16
	show                              int32
	instance                          windows.Handle
	idList                            unsafe.Pointer
	class                             *uint16
	classKey                          windows.Handle
	hotKey                            uint32
	iconOrMonitor, process            windows.Handle
}

func startWindowsRedirector(ctx context.Context, path, pipe string) (windows.Handle, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	verb, err := windows.UTF16PtrFromString("runas")
	if err != nil {
		return 0, err
	}
	file, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	args, err := windows.UTF16PtrFromString(syscall.EscapeArg(pipe))
	if err != nil {
		return 0, err
	}
	info := shellExecuteInfo{size: uint32(unsafe.Sizeof(shellExecuteInfo{})), mask: 0x40 | 0x100 | 0x400, verb: verb, file: file, parameters: args}
	call := windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteExW")
	// SAFETY: info has the documented SDK layout; all UTF-16 pointers remain
	// reachable throughout this synchronous call, and the returned handle is owned.
	ok, _, err := call.Call(uintptr(unsafe.Pointer(&info))) //nolint:gosec // This native ABI requires the SDK-layout pointer with the lifetime documented above.
	runtime.KeepAlive(info)
	if ok == 0 {
		if err == syscall.Errno(0) {
			err = errors.New("ShellExecuteExW failed")
		}
		return 0, fmt.Errorf("start elevated Windows redirector: %w", err)
	}
	if info.process == 0 {
		return 0, errors.New("windows redirector launch returned no owned process handle")
	}
	return info.process, nil
}

func (r *windowsRedirector) Launch(ctx context.Context) error {
	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	r.launchOnce.Do(func() {
		defer close(r.launchDone)
		r.launchErr = r.launch(ctx)
		if r.launchErr != nil {
			r.shutdown()
		}
	})
	return r.launchErr
}

func (r *windowsRedirector) launch(ctx context.Context) error {
	path, err := AcquireArtifact(ctx, r.confdir, r.overridePath, "windows", runtime.GOARCH)
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(r.pipeName)
	if err != nil {
		return err
	}
	security, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)")
	if err != nil {
		return err
	}
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: security}
	handle, err := windows.CreateNamedPipe(name, windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_OVERLAPPED|windows.FILE_FLAG_FIRST_PIPE_INSTANCE, windows.PIPE_TYPE_MESSAGE|windows.PIPE_READMODE_MESSAGE|windows.PIPE_REJECT_REMOTE_CLIENTS, 1, maxNativeIPCMessageSize, maxNativeIPCMessageSize, 0, &attributes)
	runtime.KeepAlive(security)
	if err != nil {
		return err
	}
	pipe := &windowsMessagePipe{handle: handle}
	processCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		cancel()
		_ = pipe.Close()
		return net.ErrClosed
	}
	r.pipe, r.cancelProcess = pipe, cancel
	r.mu.Unlock()
	r.workers.Go(func() {
		select {
		case <-ctx.Done():
			r.shutdown()
		case <-r.closedCh:
		}
	})
	process, err := r.start(processCtx, path, r.pipeName)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.process = process
	r.mu.Unlock()
	r.workers.Go(func() {
		err := r.waitProcess(process)
		r.mu.Lock()
		r.processErr = err
		r.mu.Unlock()
		close(r.processDone)
		r.shutdown()
	})
	connection, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	if err := pipe.connect(connection); err != nil {
		return fmt.Errorf("connect Windows redirector IPC: %w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return net.ErrClosed
	}
	r.ready = true
	return nil
}

func (r *windowsRedirector) waitProcess(process windows.Handle) error {
	for {
		state, err := windows.WaitForSingleObject(process, 250)
		if err != nil || state == windows.WAIT_OBJECT_0 {
			return err
		}
		select {
		case <-r.closedCh:
			state, err = windows.WaitForSingleObject(process, 1000)
			if err != nil || state == windows.WAIT_OBJECT_0 {
				return err
			}
			if err := windows.TerminateProcess(process, 1); err != nil {
				return fmt.Errorf("stop owned Windows redirector: %w", err)
			}
			state, err = windows.WaitForSingleObject(process, 5000)
			if err != nil {
				return err
			}
			if state != windows.WAIT_OBJECT_0 {
				return errors.New("owned Windows redirector did not exit after termination")
			}
			return nil
		default:
		}
	}
}

func (r *windowsRedirector) channel() (*windowsMessagePipe, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, net.ErrClosed
	}
	if !r.ready {
		return nil, errors.New("windows redirector has not launched")
	}
	return r.pipe, nil
}

func (r *windowsRedirector) SetIntercept(ctx context.Context, spec string) error {
	conf, err := EncodeInterceptSpec(spec, uint32(os.Getpid()))
	if err != nil {
		return err
	}
	return r.write(ctx, &FromProxy{Message: &FromProxy_InterceptConf{InterceptConf: conf}})
}

func (r *windowsRedirector) WritePacket(ctx context.Context, packet *Packet) error {
	if packet == nil {
		return errors.New("native redirector packet is nil")
	}
	return r.write(ctx, &FromProxy{Message: &FromProxy_Packet{Packet: packet}})
}

func (r *windowsRedirector) write(ctx context.Context, message *FromProxy) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	data, err := encodeNativeProxy(message)
	if err != nil {
		return err
	}
	select {
	case r.writeGate <- struct{}{}:
		defer func() { <-r.writeGate }()
	case <-ctx.Done():
		return ctx.Err()
	case <-r.closedCh:
		return net.ErrClosed
	}
	pipe, err := r.channel()
	if err != nil {
		return err
	}
	n, err := pipe.write(ctx, data)
	if err != nil {
		if ctx.Err() == nil || n != 0 {
			r.shutdown()
		}
		return err
	}
	return nil
}

func (r *windowsRedirector) ReadPacket(ctx context.Context) (*PacketWithMeta, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case r.readGate <- struct{}{}:
		defer func() { <-r.readGate }()
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-r.closedCh:
		return nil, net.ErrClosed
	}
	pipe, err := r.channel()
	if err != nil {
		return nil, err
	}
	data := make([]byte, maxNativeIPCMessageSize+1)
	n, err := pipe.read(ctx, data)
	if err != nil {
		if ctx.Err() == nil || n != 0 {
			r.shutdown()
		}
		return nil, errors.Join(net.ErrClosed, err)
	}
	packet, err := decodeNativePacket(data[:n])
	if err != nil {
		r.shutdown()
		return nil, errors.Join(net.ErrClosed, err)
	}
	return packet, nil
}

func (r *windowsRedirector) shutdown() {
	r.shutdownOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		pipe, cancel, process := r.pipe, r.cancelProcess, r.process
		close(r.closedCh)
		r.mu.Unlock()
		if pipe != nil {
			r.closeErr = errors.Join(r.closeErr, pipe.Close())
		}
		if process != 0 {
			<-r.processDone
		}
		if cancel != nil {
			cancel()
		}
	})
}

func (r *windowsRedirector) Close() error {
	r.shutdown()
	r.launchOnce.Do(func() {
		r.launchErr = net.ErrClosed
		close(r.launchDone)
	})
	<-r.launchDone
	r.workers.Wait()
	r.processHandleOnce.Do(func() {
		if r.process != 0 {
			r.closeErr = errors.Join(r.closeErr, windows.CloseHandle(r.process))
		}
	})
	return errors.Join(r.closeErr, r.processErr)
}
