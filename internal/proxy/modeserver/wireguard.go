// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modeserver

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/netstack"
	"github.com/zchee/mitmproxy-go/internal/wireguard"
)

type wireguardSource struct {
	ctx         context.Context
	cancel      context.CancelFunc
	server      *wireguard.Server
	stack       *netstack.Stack
	once        sync.Once
	done        chan struct{}
	monitorDone chan struct{}
	workers     sync.WaitGroup
	err         error
}

func (s *wireguardSource) Close() error {
	s.once.Do(func() {
		s.cancel()
		serverErr := s.server.Close()
		stackErr := s.stack.Close()
		<-s.done
		s.err = errors.Join(serverErr, stackErr)
	})
	return s.err
}

func (i *Instance) startWireGuard(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		i.state.Store(&instanceState{err: err})
		return err
	}
	path := i.mode.Common().Data
	if path == "" {
		path = filepath.Join(i.confDir, "wireguard.conf")
	}
	if rest, ok := strings.CutPrefix(path, "~/"); ok || path == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			i.state.Store(&instanceState{err: err})
			return err
		}
		path = filepath.Join(home, rest)
	}
	configuration, err := wireguard.LoadConfig(path)
	if err != nil {
		i.state.Store(&instanceState{err: err})
		return err
	}
	lifetime, cancel := context.WithCancel(ctx)
	stack, err := netstack.New(lifetime)
	if err != nil {
		cancel()
		i.state.Store(&instanceState{err: err})
		return err
	}
	socket, err := new(net.ListenConfig).ListenPacket(lifetime, "udp", net.JoinHostPort(i.host, strconv.Itoa(i.port)))
	if err != nil {
		cancel()
		_ = stack.Close()
		i.state.Store(&instanceState{err: err})
		return err
	}
	server, err := wireguard.New(lifetime, socket, configuration, stack, i.logger)
	if err != nil {
		cancel()
		_ = stack.Close()
		i.state.Store(&instanceState{err: err})
		return err
	}
	if err := ctx.Err(); err != nil {
		cancel()
		_ = server.Close()
		_ = stack.Close()
		i.state.Store(&instanceState{err: err})
		return err
	}
	addr := server.Addr().(*net.UDPAddr)
	clientConfigurations, err := configuration.ClientConfigs(addr.IP.String(), uint16(addr.Port))
	if err != nil {
		cancel()
		_ = server.Close()
		_ = stack.Close()
		i.state.Store(&instanceState{err: err})
		return err
	}
	source := &wireguardSource{ctx: lifetime, cancel: cancel, server: server, stack: stack, done: make(chan struct{}), monitorDone: make(chan struct{})}
	state := &instanceState{wireguard: source, addrs: []connection.Address{{Host: addr.IP.String(), Port: addr.Port}}}
	i.state.Store(state)
	go i.serveWireGuard(source)
	go func() {
		defer close(source.monitorDone)
		<-server.Done()
		unexpected := lifetime.Err() == nil
		err := source.Close()
		if unexpected {
			err = errors.Join(err, errors.New("WireGuard server stopped unexpectedly"))
		}
		i.state.CompareAndSwap(state, &instanceState{err: err})
	}()
	i.logger.Info(i.mode.Description() + " listening at " + formatAddrs(state.addrs) + ".")
	for _, clientConfiguration := range clientConfigurations {
		i.logger.Info(clientConfiguration)
	}
	return nil
}

func (i *Instance) serveWireGuard(source *wireguardSource) {
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
					i.logger.Error("Handling WireGuard TCP connection", "error", err)
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
					i.logger.Error("Handling WireGuard UDP connection", "error", err)
				}
			})
		}
	}
}
