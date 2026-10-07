// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package readfile

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"time"
)

const cleanupTimeout = 5 * time.Second

type loaderCleanup struct {
	closer   io.Closer
	loaded   <-chan struct{}
	finished chan struct{}
	once     sync.Once
	err      error
}

func (c *loaderCleanup) start() {
	c.once.Do(func() {
		go func() {
			defer close(c.finished)
			select {
			case <-c.loaded:
				return
			default:
			}
			if c.closer != nil {
				c.err = c.closer.Close()
				if errors.Is(c.err, os.ErrClosed) {
					c.err = nil
				}
			}
			<-c.loaded
		}()
	})
}

func (c *loaderCleanup) wait(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, cleanupTimeout)
	defer cancel()
	select {
	case <-c.finished:
		return c.err
	case <-ctx.Done():
		return ctx.Err()
	}
}
