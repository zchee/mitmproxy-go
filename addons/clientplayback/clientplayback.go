// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package clientplayback replays saved HTTP requests through the proxy core.
package clientplayback

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flowio"
	"github.com/zchee/mitmproxy-go/internal/proxy"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
	"github.com/zchee/mitmproxy-go/internal/proxy/layers/httplayer"
	"github.com/zchee/mitmproxy-go/internal/proxy/modespec"
	"github.com/zchee/mitmproxy-go/master"
	"github.com/zchee/mitmproxy-go/options"
)

const (
	maxReplayBytes       = 512 << 20
	maxReplayFlows       = 100_000
	maxConcurrentReplays = 256
)

// ClientPlayback owns the replay queue inside the master's dispatch domain.
// Background workers use Master.Do for every queue or flow-state access.
type ClientPlayback struct {
	master  *master.Master
	queue   []*flow.HTTPFlow
	pending map[*flow.HTTPFlow]bool
	active  int
	wake    chan struct{}
	cancel  context.CancelFunc
	done    chan struct{}
}

// New returns a client replay addon using m's options, commands and lifecycle.
func New(m *master.Master) *ClientPlayback {
	return &ClientPlayback{master: m, pending: make(map[*flow.HTTPFlow]bool), wake: make(chan struct{}, 1)}
}

// Name identifies the addon with upstream's spelling.
func (*ClientPlayback) Name() string { return "clientplayback" }

// Load registers the upstream options and replay commands.
func (c *ClientPlayback) Load(ctx context.Context, l *addon.Loader) error {
	if err := l.AddOption(ctx, "client_replay", options.TypeSeq, []string{}, "Replay client requests from a saved file."); err != nil {
		return err
	}
	if err := l.AddOption(ctx, "client_replay_concurrency", options.TypeInt, 1, "Concurrency limit on in-flight client replay requests. Currently the only valid values are 1 and -1 (no limit)."); err != nil {
		return err
	}
	commands := []struct {
		name   string
		fn     any
		params []string
		help   string
	}{
		{"replay.client", c.start, []string{"flows"}, "Add flows to the replay queue, skipping flows that can't be replayed."},
		{"replay.client.stop", c.stop, nil, "Clear the replay queue."},
		{"replay.client.count", c.count, nil, "Approximate number of flows queued for replay."},
		{"replay.client.file", c.loadFile, []string{"path"}, "Load flows from file, and add them to the replay queue."},
	}
	for _, cmd := range commands {
		if err := l.AddCommand(cmd.name, cmd.fn, command.WithParams(cmd.params...), command.WithHelp(cmd.help)); err != nil {
			return err
		}
	}
	return nil
}

func (c *ClientPlayback) check(f flow.Flow) string {
	if f == nil {
		return "Can only replay HTTP flows."
	}
	if f.Common().Live {
		return "Can't replay live flow."
	}
	if f.Common().Intercepted() {
		return "Can't replay intercepted flow."
	}
	h, ok := f.(*flow.HTTPFlow)
	if !ok || h == nil {
		return "Can only replay HTTP flows."
	}
	if _, ok := c.pending[h]; ok {
		return "Can't replay live flow."
	}
	if h.Request == nil {
		return "Can't replay flow with missing request."
	}
	if h.Request.RawContent == nil {
		return "Can't replay flow with missing content."
	}
	if h.WebSocket != nil {
		return "Can't replay WebSocket flows."
	}
	if h.Request.IsHTTP2() {
		return "Can't replay HTTP/2 flows: HTTP/2 is not supported yet."
	}
	if h.Request.IsHTTP3() {
		return "Can't replay HTTP/3 flows: HTTP/3 is not supported yet."
	}
	return ""
}

func (c *ClientPlayback) start(ctx context.Context, flows []flow.Flow) error {
	var updated []flow.Flow
	for _, f := range flows {
		if message := c.check(f); message != "" {
			slog.WarnContext(ctx, message)
			continue
		}
		if len(c.queue) >= maxReplayFlows {
			slog.WarnContext(ctx, "Client replay queue exceeds 100000 flows.")
			break
		}
		h := f.(*flow.HTTPFlow)
		h.Backup()
		h.IsReplay = new("request")
		h.Response = nil
		h.Error = nil
		c.queue = append(c.queue, h)
		c.pending[h] = false
		updated = append(updated, h)
	}
	c.notify()
	return c.master.Addons.Trigger(ctx, addon.UpdateHook{Flows: updated})
}

func (c *ClientPlayback) stop(ctx context.Context) error {
	updated := make([]flow.Flow, 0, len(c.queue))
	for _, f := range c.queue {
		if err := f.Revert(); err != nil {
			return err
		}
		delete(c.pending, f)
		updated = append(updated, f)
	}
	c.queue = nil
	if err := c.master.Addons.Trigger(ctx, addon.UpdateHook{Flows: updated}); err != nil {
		return err
	}
	slog.Log(ctx, addon.LevelAlert, "Client replay queue cleared.")
	return nil
}

func (c *ClientPlayback) count(context.Context) int { return len(c.queue) + c.active }

func (c *ClientPlayback) loadFile(ctx context.Context, path command.Path) error {
	flows, err := c.readFiles(ctx, []string{string(path)})
	if err != nil {
		return &command.Error{Err: err}
	}
	return c.start(ctx, flows)
}

func (c *ClientPlayback) readFiles(ctx context.Context, paths []string) ([]flow.Flow, error) {
	var flows []flow.Flow
	remaining := int64(maxReplayBytes)
	for _, path := range paths {
		expanded, err := command.PathType.Parse(ctx, c.master.Commands, path)
		if err != nil {
			return nil, err
		}
		file, err := os.Open(string(expanded.(command.Path)))
		if err != nil {
			if pe, ok := errors.AsType[*os.PathError](err); ok {
				return nil, pe.Err
			}
			return nil, err
		}
		info, err := file.Stat()
		if err != nil {
			return nil, errors.Join(err, file.Close())
		}
		if info.Size() > remaining {
			return nil, errors.Join(errors.New("client replay files exceed the 512 MiB or 100000 flow limit"), file.Close())
		}
		limited := &io.LimitedReader{R: file, N: remaining + 1}
		reader := flowio.NewReader(limited)
		for {
			f, err := reader.Next()
			if limited.N == 0 || len(flows) >= maxReplayFlows && err == nil {
				return nil, errors.Join(errors.New("client replay files exceed the 512 MiB or 100000 flow limit"), file.Close())
			}
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return nil, errors.Join(err, file.Close())
			}
			flows = append(flows, f)
		}
		remaining = limited.N - 1
		if err := file.Close(); err != nil {
			return nil, err
		}
	}
	return flows, nil
}

// Configure loads requested flow files and validates the concurrency option.
func (c *ClientPlayback) Configure(ctx context.Context, updated map[string]struct{}) error {
	if _, ok := updated["client_replay_concurrency"]; ok {
		value := c.master.Options.Int("client_replay_concurrency")
		if value != 1 && value != -1 {
			return &options.OptionsError{Err: errors.New("Currently the only valid client_replay_concurrency values are -1 and 1.")} //nolint:staticcheck // Preserve upstream's user-facing diagnostic.
		}
		c.notify()
	}
	if _, ok := updated["client_replay"]; ok {
		paths := c.master.Options.Seq("client_replay")
		if len(paths) > 0 {
			flows, err := c.readFiles(ctx, paths)
			if err != nil {
				return &options.OptionsError{Err: err}
			}
			return c.start(ctx, flows)
		}
	}
	return nil
}

// Running starts the replay scheduler without inheriting a dispatch frame.
func (c *ClientPlayback) Running(ctx context.Context) error {
	if c.cancel != nil {
		return nil
	}
	base := context.Background()
	if _, err := addon.Concurrent(ctx, func(clean context.Context) error { base = context.WithoutCancel(clean); return nil }); err != nil && !errors.Is(err, addon.ErrSyncContext) {
		return err
	}
	replayCtx, cancel := context.WithCancel(base)
	c.cancel = cancel
	c.done = make(chan struct{})
	go c.playback(replayCtx, c.done)
	return nil
}

// Done cancels every replay and joins workers outside the dispatch lock.
// Synchronous removal cannot yield; its canceled workers finish after dispatch.
func (c *ClientPlayback) Done(ctx context.Context) error {
	cancel, done := c.cancel, c.done
	c.cancel = nil
	if cancel == nil {
		return nil
	}
	cancel()
	_, err := addon.Concurrent(ctx, func(context.Context) error { <-done; return nil })
	if errors.Is(err, addon.ErrSyncContext) {
		return nil
	}
	return err
}

func (c *ClientPlayback) notify() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *ClientPlayback) playback(ctx context.Context, done chan struct{}) {
	defer close(done)
	var workers sync.WaitGroup
	defer workers.Wait()
	for {
		var f *flow.HTTPFlow
		var mode modespec.Mode
		var modeErr error
		cfg := proxy.Config{Manager: c.master.Addons, Options: c.master.Options}
		if err := c.master.Do(ctx, func(context.Context) error {
			limit := 1
			if c.master.Options.Int("client_replay_concurrency") == -1 {
				limit = maxConcurrentReplays
			}
			if len(c.queue) == 0 || c.active >= limit {
				return nil
			}
			f = c.queue[0]
			c.queue[0] = nil
			c.queue = c.queue[1:]
			c.pending[f] = true
			c.active++
			if modes := c.master.Options.Seq("mode"); len(modes) > 0 && strings.HasPrefix(modes[0], "upstream:") {
				mode, modeErr = modespec.Parse(modes[0])
			}
			if p, ok := c.master.Addons.Get("proxyserver").(interface{ Dialer() layer.Dialer }); ok {
				cfg.Dialer = p.Dialer()
			}
			return nil
		}); err != nil {
			return
		}
		if f != nil {
			workers.Go(func() { c.replay(ctx, cfg, f, mode, modeErr) })
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-c.wake:
		}
	}
}

func (c *ClientPlayback) replay(ctx context.Context, cfg proxy.Config, f *flow.HTTPFlow, mode modespec.Mode, modeErr error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			slog.ErrorContext(ctx, "Client replay has crashed!", "error", fmt.Sprint(recovered))
		}
		_ = c.master.Do(context.WithoutCancel(ctx), func(context.Context) error { delete(c.pending, f); c.active--; return nil })
		c.notify()
	}()
	err := modeErr
	if err == nil {
		err = proxy.Replay(ctx, cfg, f, mode, httplayer.Replay)
	}
	if err != nil && ctx.Err() == nil {
		slog.ErrorContext(ctx, "Client replay has crashed!", "error", err)
	}
}
