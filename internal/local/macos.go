// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package local

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"time"
)

var errMacOSPacketUnsupported = errors.New("macOS redirector supports streams, not packet I/O")

// NewMacOSRedirector creates a process-lifetime macOS redirector controller.
// Launch uses the existing /Applications/Mitmproxy Redirector.app by default;
// overridePath may select a regular executable or an app directory instead.
// confdir is the artifact cache directory used when validating that override.
// Construction does not start a process, install an app, or approve an extension.
func NewMacOSRedirector(confdir, overridePath string) Redirector {
	return &macOSRedirector{
		confdir:        confdir,
		overridePath:   overridePath,
		socketPath:     "/tmp/mitmproxy-" + strconv.Itoa(os.Getpid()),
		connectTimeout: 5 * time.Second,
		closedCh:       make(chan struct{}),
		launchDone:     make(chan struct{}),
		writeGate:      make(chan struct{}, 1),
	}
}

type macOSRedirector struct {
	confdir, overridePath, socketPath string
	connectTimeout                    time.Duration
	launchOnce, shutdownOnce          sync.Once
	launchDone, closedCh              chan struct{}
	writeGate                         chan struct{}
	workers                           sync.WaitGroup
	mu                                sync.Mutex
	closed                            bool
	cancel                            context.CancelFunc
	listener                          *net.UnixListener
	control                           *net.UnixConn
	launchErr, closeErr               error
}

func (r *macOSRedirector) Launch(ctx context.Context) error {
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

func (r *macOSRedirector) launch(ctx context.Context) error {
	path := r.overridePath
	if path == "" {
		path = "/Applications/Mitmproxy Redirector.app"
	}
	path, err := AcquireArtifact(ctx, r.confdir, path, "darwin", runtime.GOARCH)
	if err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		app, err := filepath.EvalSymlinks(path)
		if err != nil {
			return err
		}
		path, err = filepath.EvalSymlinks(filepath.Join(path, "Contents", "MacOS", "Mitmproxy Redirector"))
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(app, path)
		if err != nil || !filepath.IsLocal(relative) {
			return errors.New("macOS redirector executable escapes app directory")
		}
		if _, err := AcquireArtifact(ctx, r.confdir, path, "darwin", runtime.GOARCH); err != nil {
			return err
		}
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: r.socketPath, Net: "unix"})
	if err != nil {
		return fmt.Errorf("listen for macOS redirector: %w", err)
	}
	life, cancel := context.WithCancel(ctx)
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		cancel()
		_ = listener.Close()
		return net.ErrClosed
	}
	r.listener, r.cancel = listener, cancel
	r.mu.Unlock()
	r.workers.Go(func() {
		<-life.Done()
		r.shutdown()
	})

	startup, stop := context.WithTimeout(life, r.connectTimeout)
	defer stop()
	command := exec.CommandContext(startup, path, r.socketPath) //nolint:gosec // The operator-selected executable is validated and arguments bypass a shell.
	command.Stdout, command.Stderr = io.Discard, io.Discard
	command.WaitDelay = time.Second
	if err := command.Run(); err != nil {
		if life.Err() != nil {
			return r.lifecycleError(ctx)
		}
		if startup.Err() != nil {
			return startup.Err()
		}
		return fmt.Errorf("launch macOS redirector: %w", err)
	}
	deadline, _ := startup.Deadline()
	if err := listener.SetDeadline(deadline); err != nil {
		return r.lifecycleError(ctx)
	}
	control, err := listener.AcceptUnix()
	if err != nil {
		if life.Err() != nil {
			return r.lifecycleError(ctx)
		}
		return fmt.Errorf("establish macOS control channel: %w", err)
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		_ = control.Close()
		return r.lifecycleError(ctx)
	}
	r.control = control
	r.mu.Unlock()
	if err := listener.SetDeadline(time.Time{}); err != nil {
		return err
	}
	r.workers.Go(func() {
		// Upstream sends no control responses: EOF or any input is terminal.
		var data [1]byte
		_, _ = control.Read(data[:])
		r.shutdown()
	})
	return nil
}

func (r *macOSRedirector) SetIntercept(ctx context.Context, spec string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	conf, err := EncodeInterceptSpec(spec, uint32(os.Getpid()))
	if err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-r.closedCh:
		return net.ErrClosed
	case r.writeGate <- struct{}{}:
		defer func() { <-r.writeGate }()
	}
	r.mu.Lock()
	control, closed := r.control, r.closed
	r.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	if control == nil {
		return errors.New("macOS redirector has not launched")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	cancelDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = control.SetWriteDeadline(time.Now())
		close(cancelDone)
	})
	err = writeIPC(control, conf)
	if !stop() {
		<-cancelDone
	}
	resetErr := control.SetWriteDeadline(time.Time{})
	if err != nil || resetErr != nil {
		// A partial frame cannot be retried safely on the control stream.
		r.shutdown()
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil || resetErr != nil {
		return errors.Join(net.ErrClosed, err, resetErr)
	}
	return nil
}

func (r *macOSRedirector) ReadPacket(ctx context.Context) (*PacketWithMeta, error) {
	return nil, r.packetError(ctx)
}

func (r *macOSRedirector) WritePacket(ctx context.Context, _ *Packet) error {
	return r.packetError(ctx)
}

func (r *macOSRedirector) packetError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-r.closedCh:
		return net.ErrClosed
	default:
		return errMacOSPacketUnsupported
	}
}

func (r *macOSRedirector) lifecycleError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return net.ErrClosed
}

func (r *macOSRedirector) shutdown() {
	r.shutdownOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		listener, control, cancel := r.listener, r.control, r.cancel
		close(r.closedCh)
		r.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		if control != nil {
			r.closeErr = errors.Join(r.closeErr, control.Close())
		}
		if listener != nil {
			r.closeErr = errors.Join(r.closeErr, listener.Close())
		}
	})
}

func (r *macOSRedirector) Close() error {
	r.shutdown()
	r.launchOnce.Do(func() {
		r.launchErr = net.ErrClosed
		close(r.launchDone)
	})
	<-r.launchDone
	r.workers.Wait()
	return r.closeErr
}
