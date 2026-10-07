// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package local

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// NewLinuxRedirector creates a process-lifetime native Linux packet controller.
// Construction is inert. Launch acquires a pinned executable (or validates the
// override), then follows the native sudo launch protocol. Packet messages use
// Unix datagram boundaries, not a length prefix. Close reaps the owned process.
func NewLinuxRedirector(confdir, overridePath string) Redirector {
	return &linuxRedirector{confdir: confdir, overridePath: overridePath, hostOS: runtime.GOOS, runtimeParent: os.TempDir(), start: startLinuxRedirector, launchDone: make(chan struct{}), closedCh: make(chan struct{}), processDone: make(chan struct{}), readGate: make(chan struct{}, 1), writeGate: make(chan struct{}, 1)}
}

type linuxRedirector struct {
	confdir, overridePath, hostOS string
	runtimeParent                 string
	start                         func(context.Context, string, string) (*exec.Cmd, io.ReadCloser, error)
	launchOnce, shutdownOnce      sync.Once
	launchDone, closedCh          chan struct{}
	processDone                   chan struct{}
	readGate, writeGate           chan struct{}
	workers                       sync.WaitGroup
	mu                            sync.Mutex
	closed, ready, started        bool
	conn                          *net.UnixConn
	dir, peer                     string
	cancelProcess                 context.CancelFunc
	launchErr, closeErr           error
}

func startLinuxRedirector(ctx context.Context, path, dir string) (*exec.Cmd, io.ReadCloser, error) {
	preflight := exec.CommandContext(ctx, "sudo", "echo", "-n")
	preflight.Stdin, preflight.Stdout, preflight.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := preflight.Run(); err != nil {
		return nil, nil, fmt.Errorf("elevate Linux redirector privileges: %w", err)
	}
	cmd := exec.CommandContext(ctx, "sudo", "--non-interactive", "--preserve-env", path, dir) //nolint:gosec // The executable is verified or operator-selected, and arguments bypass a shell.
	cmd.Stderr = os.Stderr
	cmd.WaitDelay = time.Second
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		_ = stdout.Close()
		return nil, nil, fmt.Errorf("start Linux redirector: %w", err)
	}
	return cmd, stdout, nil
}

func (r *linuxRedirector) Launch(ctx context.Context) error {
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

func (r *linuxRedirector) launch(ctx context.Context) error {
	if r.hostOS != "linux" {
		return fmt.Errorf("linux redirector cannot launch on %s", r.hostOS)
	}
	path, err := AcquireArtifact(ctx, r.confdir, r.overridePath, "linux", runtime.GOARCH)
	if err != nil {
		return err
	}
	// Unix socket addresses have a short fixed limit independent of confdir.
	// Keep the runtime beneath the OS temporary root, as the native host does.
	dir, err := os.MkdirTemp(r.runtimeParent, "")
	if err != nil {
		return err
	}
	processCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		cancel()
		_ = os.RemoveAll(dir)
		return net.ErrClosed
	}
	r.dir, r.cancelProcess = dir, cancel
	r.mu.Unlock()
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: filepath.Join(dir, "mitmproxy"), Net: "unixgram"})
	if err != nil {
		return err
	}
	if err := errors.Join(conn.SetReadBuffer(2*maxNativeIPCMessageSize), conn.SetWriteBuffer(2*maxNativeIPCMessageSize)); err != nil {
		_ = conn.Close()
		return err
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		_ = conn.Close()
		return net.ErrClosed
	}
	r.conn = conn
	r.mu.Unlock()
	r.workers.Go(func() {
		select {
		case <-ctx.Done():
			r.shutdown()
		case <-r.closedCh:
		}
	})
	cmd, stdout, err := r.start(processCtx, path, dir)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.started = true
	r.mu.Unlock()
	r.workers.Go(func() {
		_ = cmd.Wait()
		close(r.processDone)
		r.shutdown()
	})
	type startupResult struct {
		path string
		err  error
	}
	result := make(chan startupResult, 1)
	r.workers.Go(func() {
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 256), 4096)
		if !scanner.Scan() {
			err := scanner.Err()
			if err == nil {
				err = io.EOF
			}
			result <- startupResult{err: err}
			return
		}
		result <- startupResult{path: scanner.Text()}
	})
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	var peer string
	select {
	case response := <-result:
		if response.err != nil {
			return fmt.Errorf("read Linux redirector startup: %w", response.err)
		}
		peer = response.path
	case <-ctx.Done():
		return ctx.Err()
	case <-r.closedCh:
		return net.ErrClosed
	case <-timer.C:
		return errors.New("linux redirector connection timeout")
	}
	if filepath.Clean(peer) != filepath.Join(dir, "redirector") {
		return errors.New("linux redirector advertised an endpoint outside its runtime directory")
	}
	if err := connectNativeDatagram(conn, peer); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return net.ErrClosed
	}
	r.peer, r.ready = peer, true
	return nil
}

func (r *linuxRedirector) SetIntercept(ctx context.Context, spec string) error {
	conf, err := EncodeInterceptSpec(spec, uint32(os.Getpid()))
	if err != nil {
		return err
	}
	// The native eBPF table truncates at twenty actions. Reject overflow so the
	// final own-PID exclusion cannot be silently discarded by the executable.
	if len(conf.Actions) > 20 {
		return errors.New("linux redirector intercept rules exceed native table capacity")
	}
	return r.write(ctx, &FromProxy{Message: &FromProxy_InterceptConf{InterceptConf: conf}})
}

func (r *linuxRedirector) WritePacket(ctx context.Context, packet *Packet) error {
	if packet == nil {
		return errors.New("native redirector packet is nil")
	}
	return r.write(ctx, &FromProxy{Message: &FromProxy_Packet{Packet: packet}})
}

func (r *linuxRedirector) channel() (*net.UnixConn, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, net.ErrClosed
	}
	if !r.ready {
		return nil, errors.New("linux redirector has not launched")
	}
	return r.conn, nil
}

func (r *linuxRedirector) write(ctx context.Context, message *FromProxy) error {
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
	conn, err := r.channel()
	if err != nil {
		return err
	}
	canceled := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = conn.SetWriteDeadline(time.Now())
		close(canceled)
	})
	n, err := conn.Write(data)
	if !stop() {
		<-canceled
	}
	resetErr := conn.SetWriteDeadline(time.Time{})
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err != nil || resetErr != nil {
		r.shutdown()
		return errors.Join(net.ErrClosed, err, resetErr)
	}
	return nil
}

func (r *linuxRedirector) ReadPacket(ctx context.Context) (*PacketWithMeta, error) {
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
	conn, err := r.channel()
	if err != nil {
		return nil, err
	}
	data := make([]byte, maxNativeIPCMessageSize+1)
	canceled := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = conn.SetReadDeadline(time.Now())
		close(canceled)
	})
	n, _, flags, _, err := conn.ReadMsgUnix(data, nil)
	if !stop() {
		<-canceled
	}
	resetErr := conn.SetReadDeadline(time.Time{})
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if nativeDatagramTruncated(flags) || n > maxNativeIPCMessageSize {
		err = errNativeMessageTooLarge
	}
	if err == nil && n == 0 {
		err = io.EOF
	}
	if err != nil || resetErr != nil {
		r.shutdown()
		return nil, errors.Join(net.ErrClosed, err, resetErr)
	}
	packet, err := decodeNativePacket(data[:n])
	if err != nil {
		r.shutdown()
		return nil, errors.Join(net.ErrClosed, err)
	}
	return packet, nil
}

func (r *linuxRedirector) shutdown() {
	r.shutdownOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		conn, peer, dir, cancel, started := r.conn, r.peer, r.dir, r.cancelProcess, r.started
		close(r.closedCh)
		r.mu.Unlock()
		if conn != nil {
			if peer != "" {
				_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
				_, _ = conn.Write(nil)
			}
			_ = conn.SetReadDeadline(time.Now())
		}
		if started {
			timer := time.NewTimer(time.Second)
			select {
			case <-r.processDone:
			case <-timer.C:
			}
			timer.Stop()
		}
		if conn != nil {
			r.closeErr = errors.Join(r.closeErr, conn.Close())
		}
		if cancel != nil {
			cancel()
		}
		if dir != "" {
			r.closeErr = errors.Join(r.closeErr, os.RemoveAll(dir))
		}
	})
}

func (r *linuxRedirector) Close() error {
	r.shutdown()
	r.launchOnce.Do(func() {
		r.launchErr = net.ErrClosed
		close(r.launchDone)
	})
	<-r.launchDone
	r.workers.Wait()
	return r.closeErr
}
