// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package cmdline

import (
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
)

// Signals calls shutdown when SIGINT or SIGTERM arrives and ignores SIGPIPE
// on Unix, as mitmdump does. The returned function unregisters the handlers
// and waits for the signal goroutine to exit; it must not be called from
// shutdown itself. SIGPIPE remains ignored for the lifetime of the process.
func Signals(shutdown func()) func() {
	if runtime.GOOS != "windows" {
		signal.Ignore(syscall.SIGPIPE)
	}
	incoming := make(chan os.Signal, 1)
	signal.Notify(incoming, os.Interrupt, syscall.SIGTERM)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			select {
			case <-incoming:
				shutdown()
			case <-stop:
				return
			}
		}
	})
	return sync.OnceFunc(func() {
		signal.Stop(incoming)
		close(stop)
		wg.Wait()
	})
}
