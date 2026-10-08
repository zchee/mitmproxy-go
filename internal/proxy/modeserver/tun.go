// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"context"
	"errors"
	"sync"

	"github.com/zchee/mitmproxy-go/internal/netstack"
	"github.com/zchee/mitmproxy-go/internal/tun"
)

type tunSource struct {
	ctx         context.Context
	cancel      context.CancelFunc
	stack       *netstack.Stack
	name        string
	once        sync.Once
	done        chan struct{}
	monitorDone chan struct{}
	bridgeDone  chan struct{}
	workers     sync.WaitGroup
	bridgeErr   error
	err         error
}

func (s *tunSource) Close() error {
	s.once.Do(func() {
		s.cancel()
		<-s.bridgeDone
		bridgeErr := s.bridgeErr
		// Serve joins cancellation with any device-close error. Suppress only
		// the canceled lifetime, retaining genuine device cleanup failures.
		if joined, ok := bridgeErr.(interface{ Unwrap() []error }); ok {
			var errs []error
			for _, err := range joined.Unwrap() {
				if err != s.ctx.Err() {
					errs = append(errs, err)
				}
			}
			bridgeErr = errors.Join(errs...)
		}
		stackErr := s.stack.Close()
		<-s.done
		s.err = errors.Join(bridgeErr, stackErr)
	})
	return s.err
}

func (i *Instance) startTun(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		i.state.Store(&instanceState{err: err})
		return err
	}
	dev, err := i.openTun(i.mode.Common().Data, i.logger)
	if err != nil {
		i.state.Store(&instanceState{err: err})
		return err
	}
	name, err := dev.Name()
	if err != nil {
		err = errors.Join(err, dev.Close())
		i.state.Store(&instanceState{err: err})
		return err
	}
	lifetime, cancel := context.WithCancel(ctx)
	stack, err := netstack.New(lifetime)
	if err != nil {
		cancel()
		err = errors.Join(err, dev.Close())
		i.state.Store(&instanceState{err: err})
		return err
	}
	if err := ctx.Err(); err != nil {
		cancel()
		err = errors.Join(err, dev.Close(), stack.Close())
		i.state.Store(&instanceState{err: err})
		return err
	}
	source := &tunSource{ctx: lifetime, cancel: cancel, stack: stack, name: name, done: make(chan struct{}), monitorDone: make(chan struct{}), bridgeDone: make(chan struct{})}
	state := &instanceState{tun: source}
	i.state.Store(state)
	go i.serveTun(source)
	go func() {
		source.bridgeErr = tun.Serve(lifetime, dev, stack)
		close(source.bridgeDone)
		unexpected := lifetime.Err() == nil
		err := source.Close()
		if unexpected && err == nil {
			err = errors.New("TUN interface stopped unexpectedly")
		}
		i.state.CompareAndSwap(state, &instanceState{err: err})
		close(source.monitorDone)
	}()
	i.logger.Info("TUN interface created: " + source.name)
	return nil
}

func (i *Instance) serveTun(source *tunSource) {
	defer close(source.done)
	defer source.workers.Wait()
	for {
		select {
		case <-source.ctx.Done():
			return
		case conn, ok := <-source.stack.TCPConns():
			if !ok {
				return
			}
			if admitted, _ := i.limiter.acquire(); !admitted {
				_ = conn.Close()
				continue
			}
			source.workers.Go(func() {
				defer i.limiter.release()
				if err := i.handler.Handle(source.ctx, conn, i.mode.String(), i.top); err != nil {
					i.logger.Error("Handling TUN TCP connection", "error", err)
				}
			})
		case conn, ok := <-source.stack.UDPConns():
			if !ok {
				return
			}
			if admitted, _ := i.limiter.acquire(); !admitted {
				_ = conn.Close()
				continue
			}
			source.workers.Go(func() {
				defer i.limiter.release()
				if err := i.handler.HandlePackets(source.ctx, conn, i.mode.String(), i.top); err != nil {
					i.logger.Error("Handling TUN UDP connection", "error", err)
				}
			})
		}
	}
}
