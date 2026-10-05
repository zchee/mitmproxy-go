// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package serverplayback serves recorded HTTP responses to matching requests.
package serverplayback

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flowio"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/pyrepr"
	"github.com/zchee/mitmproxy-go/master"
	"github.com/zchee/mitmproxy-go/omap"
	"github.com/zchee/mitmproxy-go/options"
)

// ServerPlayback holds recorded flows, accessed only under addon dispatch.
type ServerPlayback struct {
	master     *master.Master
	flowmap    *omap.Map[[]*flow.HTTPFlow]
	configured bool
}

// New returns a server replay addon using m's dispatch and options registries.
func New(m *master.Master) *ServerPlayback {
	return &ServerPlayback{master: m, flowmap: omap.New[[]*flow.HTTPFlow]()}
}

// Name identifies the addon with upstream's spelling.
func (*ServerPlayback) Name() string { return "serverplayback" }

// Load registers the upstream server replay options and commands.
func (s *ServerPlayback) Load(ctx context.Context, l *addon.Loader) error {
	defs := []struct {
		name string
		typ  options.Type
		def  any
		help string
	}{
		{"server_replay_kill_extra", options.TypeBool, false, "Kill extra requests during replay (for which no replayable response was found).[Deprecated, prefer to use server_replay_extra='kill']"},
		{"server_replay_extra", options.TypeStr, "forward", "Behaviour for extra requests during replay for which no replayable response was found. Setting a numeric string value will return an empty HTTP response with the respective status code."},
		{"server_replay_reuse", options.TypeBool, false, "Don't remove flows from server replay state after use. This makes it possible to replay same response multiple times."},
		{"server_replay_nopop", options.TypeBool, false, "Deprecated alias for `server_replay_reuse`."},
		{"server_replay_refresh", options.TypeBool, true, "Refresh server replay responses by adjusting date, expires and last-modified headers, as well as adjusting cookie expiration."},
		{"server_replay_use_headers", options.TypeSeq, []string{}, "Request headers that need to match while searching for a saved flow to replay."},
		{"server_replay", options.TypeSeq, []string{}, "Replay server responses from a saved file."},
		{"server_replay_ignore_content", options.TypeBool, false, "Ignore request content while searching for a saved flow to replay."},
		{"server_replay_ignore_params", options.TypeSeq, []string{}, "Request parameters to be ignored while searching for a saved flow to replay."},
		{"server_replay_ignore_payload_params", options.TypeSeq, []string{}, "Request payload parameters (application/x-www-form-urlencoded or multipart/form-data) to be ignored while searching for a saved flow to replay."},
		{"server_replay_ignore_host", options.TypeBool, false, "Ignore request destination host while searching for a saved flow to replay."},
		{"server_replay_ignore_port", options.TypeBool, false, "Ignore request destination port while searching for a saved flow to replay."},
	}
	for _, d := range defs {
		var extra []string
		if d.name == "server_replay_extra" {
			extra = []string{"forward", "kill", "204", "400", "404", "500"}
		}
		if err := l.AddOption(ctx, d.name, d.typ, d.def, d.help, extra...); err != nil {
			return err
		}
	}
	commands := []struct {
		name   string
		fn     any
		params []string
		help   string
	}{
		{"replay.server", s.loadFlows, []string{"flows"}, "Replay server responses from flows."},
		{"replay.server.add", s.addFlows, []string{"flows"}, "Add responses from flows to server replay list."},
		{"replay.server.file", s.loadFile, []string{"path"}, ""},
		{"replay.server.stop", s.clear, nil, "Stop server replay."},
		{"replay.server.count", s.count, nil, ""},
	}
	for _, c := range commands {
		if err := l.AddCommand(c.name, c.fn, command.WithParams(c.params...), command.WithHelp(c.help)); err != nil {
			return err
		}
	}
	return nil
}

func (s *ServerPlayback) loadFlows(ctx context.Context, flows []flow.Flow) error {
	s.flowmap = omap.New[[]*flow.HTTPFlow]()
	return s.addFlows(ctx, flows)
}

func (s *ServerPlayback) addFlows(ctx context.Context, flows []flow.Flow) error {
	for _, f := range flows {
		if h, ok := f.(*flow.HTTPFlow); ok && h.Request != nil {
			key := s.hash(h)
			bucket, _ := s.flowmap.Get(key)
			s.flowmap.Set(key, append(bucket, h))
		}
	}
	return s.master.Addons.Trigger(ctx, addon.UpdateHook{Flows: []flow.Flow{}})
}

func (s *ServerPlayback) clear(ctx context.Context) error {
	s.flowmap = omap.New[[]*flow.HTTPFlow]()
	return s.master.Addons.Trigger(ctx, addon.UpdateHook{Flows: []flow.Flow{}})
}

func (s *ServerPlayback) count(context.Context) int {
	n := 0
	for _, flows := range s.flowmap.All() {
		n += len(flows)
	}
	return n
}

func (s *ServerPlayback) loadFile(ctx context.Context, path command.Path) error {
	flows, err := s.readFiles(ctx, []string{string(path)})
	if err != nil {
		return &command.Error{Err: err}
	}
	return s.loadFlows(ctx, flows)
}

const (
	maxReplayBytes = 512 << 20
	maxReplayFlows = 100_000
)

func (s *ServerPlayback) readFiles(ctx context.Context, paths []string) ([]flow.Flow, error) {
	var flows []flow.Flow
	remaining := int64(maxReplayBytes)
	for _, path := range paths {
		expanded, err := command.PathType.Parse(ctx, s.master.Commands, path)
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
			return nil, errors.Join(errors.New("server replay files exceed the 512 MiB or 100000 flow limit"), file.Close())
		}
		limit := &io.LimitedReader{R: file, N: remaining + 1}
		reader := flowio.NewReader(limit)
		for {
			f, err := reader.Next()
			if limit.N == 0 || len(flows) >= maxReplayFlows && err == nil {
				return nil, errors.Join(errors.New("server replay files exceed the 512 MiB or 100000 flow limit"), file.Close())
			}
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return nil, errors.Join(err, file.Close())
			}
			flows = append(flows, f)
		}
		remaining = limit.N - 1
		if err := file.Close(); err != nil {
			return nil, err
		}
	}
	return flows, nil
}

type tuple [2]any

func (t tuple) String() string { return "(" + pyrepr.Value(t[0]) + ", " + pyrepr.Value(t[1]) + ")" }

func (s *ServerPlayback) hash(f *flow.HTTPFlow) string {
	r := f.Request
	o := s.master.Options
	path, _, _ := strings.Cut(r.Path, "#")
	path, _, _ = strings.Cut(path, "?")
	// urlparse removes parameters from the final path segment only.
	if slash := strings.LastIndexByte(path, '/'); slash >= 0 {
		prefix, last := path[:slash+1], path[slash+1:]
		last, _, _ = strings.Cut(last, ";")
		path = prefix + last
	} else {
		path, _, _ = strings.Cut(path, ";")
	}
	key := []any{r.Scheme, strings.ToUpper(r.Method), path}
	if !o.Bool("server_replay_ignore_content") {
		ignored := o.Seq("server_replay_ignore_payload_params")
		multipart := r.MultipartForm()
		urlencoded := r.URLEncodedForm()
		switch {
		case len(ignored) > 0 && len(multipart) > 0:
			for _, p := range multipart {
				if !slices.Contains(ignored, strings.ToValidUTF8(string(p[0]), "�")) {
					key = append(key, tuple{p[0], p[1]})
				}
			}
		case len(ignored) > 0 && len(urlencoded) > 0:
			for _, p := range urlencoded {
				if !slices.Contains(ignored, p[0]) {
					key = append(key, tuple{p[0], p[1]})
				}
			}
		default:
			content := "None"
			if r.RawContent != nil {
				content = pyrepr.Bytes(r.RawContent)
			}
			key = append(key, content)
		}
	}
	if !o.Bool("server_replay_ignore_host") {
		key = append(key, r.PrettyHost())
	}
	if !o.Bool("server_replay_ignore_port") {
		key = append(key, r.Port)
	}
	ignored := o.Seq("server_replay_ignore_params")
	for _, p := range r.Query() {
		if !slices.Contains(ignored, p[0]) {
			key = append(key, p[0], p[1])
		}
	}
	if names := o.Seq("server_replay_use_headers"); len(names) > 0 {
		headers := make([]any, 0, len(names))
		for _, name := range names {
			var value any
			if v, ok := r.Headers.Lookup(name); ok {
				value = v
			}
			headers = append(headers, tuple{name, value})
		}
		key = append(key, headers)
	}
	hash := sha256.Sum256([]byte(pyrepr.Value(key)))
	return string(hash[:])
}

func (s *ServerPlayback) nextFlow(f *flow.HTTPFlow) *flow.HTTPFlow {
	key := s.hash(f)
	flows, _ := s.flowmap.Get(key)
	if s.master.Options.Bool("server_replay_reuse") || s.master.Options.Bool("server_replay_nopop") {
		for _, candidate := range flows {
			if candidate.Response != nil {
				return candidate
			}
		}
		return nil
	}
	for len(flows) > 0 {
		candidate := flows[0]
		flows[0] = nil
		flows = flows[1:]
		if len(flows) == 0 {
			s.flowmap.Delete(key)
		} else {
			s.flowmap.Set(key, flows)
		}
		if candidate.Response != nil {
			return candidate
		}
	}
	return nil
}

// Configure loads configured files once and rebuilds request keys when matching changes.
func (s *ServerPlayback) Configure(ctx context.Context, updated map[string]struct{}) error {
	o := s.master.Options
	if o.Bool("server_replay_kill_extra") {
		slog.WarnContext(ctx, "server_replay_kill_extra has been deprecated, please update your config to use server_replay_extra='kill'.")
	}
	if o.Bool("server_replay_nopop") {
		slog.ErrorContext(ctx, "server_replay_nopop has been renamed to server_replay_reuse, please update your config.")
	}
	if paths := o.Seq("server_replay"); !s.configured && len(paths) > 0 {
		s.configured = true
		flows, err := s.readFiles(ctx, paths)
		if err != nil {
			return &options.OptionsError{Err: err}
		}
		if err := s.loadFlows(ctx, flows); err != nil {
			return err
		}
	}
	for _, name := range []string{"server_replay_ignore_content", "server_replay_ignore_host", "server_replay_ignore_params", "server_replay_ignore_payload_params", "server_replay_ignore_port", "server_replay_use_headers"} {
		if _, ok := updated[name]; ok {
			var flows []flow.Flow
			for _, bucket := range s.flowmap.All() {
				for _, f := range bucket {
					flows = append(flows, f)
				}
			}
			return s.loadFlows(ctx, flows)
		}
	}
	return nil
}

// Request supplies a cloned recorded response or applies the unmatched-request policy.
func (s *ServerPlayback) Request(ctx context.Context, f *flow.HTTPFlow) error {
	if s.flowmap.Len() == 0 || f.Request == nil {
		return nil
	}
	if recorded := s.nextFlow(f); recorded != nil {
		response := recorded.Response.Clone()
		if s.master.Options.Bool("server_replay_refresh") {
			response.Refresh(0)
		}
		f.Response = response
		f.IsReplay = new("response")
		return nil
	}
	extra := s.master.Options.Str("server_replay_extra")
	if s.master.Options.Bool("server_replay_kill_extra") || extra == "kill" {
		slog.WarnContext(ctx, "server_playback: killed non-replay request "+f.Request.URL())
		return f.Kill()
	}
	if extra != "forward" {
		status, err := strconv.Atoi(extra)
		if err != nil {
			return err
		}
		response, err := httpmsg.MakeResponse(status, []byte{}, nil)
		if err != nil {
			return err
		}
		slog.WarnContext(ctx, fmt.Sprintf("server_playback: returned %s non-replay request %s", extra, f.Request.URL()))
		f.Response = response
		f.IsReplay = new("response")
	}
	return nil
}
