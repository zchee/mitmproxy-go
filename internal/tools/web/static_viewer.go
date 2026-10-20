// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package web

import (
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"uuid"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/contentviews"
	"github.com/zchee/mitmproxy-go/filter"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flowio"
	"github.com/zchee/mitmproxy-go/flowio/flowjson"
	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/version"
	"github.com/zchee/mitmproxy-go/options"
)

type viewerInput struct{ destination, rfile, definitions string }

type viewerJob struct {
	input viewerInput
	done  chan struct{}
	err   error
}

// StaticViewer exports a complete offline viewer on its own serialized worker.
// Configure captures immutable inputs; filesystem work never holds dispatch.
// Use the assembled Master's StaticViewer and Wait to observe completion.
// A failed export is logged; it does not roll back the option update.
type StaticViewer struct {
	master               *Master
	mu                   sync.Mutex
	wake                 chan struct{}
	pending, latest      *viewerJob
	published            map[viewerInput]bool
	cancel, activeCancel context.CancelFunc
	stopped              chan struct{}
	closed               bool
}

// Load registers the optional static-viewer destination, empty by default.
func (*StaticViewer) Load(ctx context.Context, loader *addon.Loader) error {
	return loader.AddOption(ctx, "web_static_viewer", options.TypeOptStr, new(""), "The path to output a static viewer.")
}

// Configure captures a destination and its input file without doing filesystem I/O.
// Repeated successful inputs are not exported again; pending inputs coalesce.
func (s *StaticViewer) Configure(_ context.Context, updated map[string]struct{}) error {
	if _, ok := updated["web_static_viewer"]; !ok {
		return nil
	}
	input := viewerInput{}
	if value := s.master.Options.OptStr("web_static_viewer"); value != nil {
		input.destination = *value
	}
	if value := s.master.Options.OptStr("rfile"); value != nil {
		input.rfile = *value
	}
	if value := s.master.Options.OptStr("protobuf_definitions"); value != nil {
		input.definitions = *value
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if s.latest != nil && s.latest.input == input {
		return nil
	}
	if s.activeCancel != nil {
		s.activeCancel()
	}
	if s.pending != nil {
		s.pending.err = context.Canceled
		close(s.pending.done)
	}
	job := &viewerJob{input: input, done: make(chan struct{})}
	s.latest, s.pending = job, nil
	if input.destination == "" || s.published[input] {
		close(job.done)
		return nil
	}
	s.pending = job
	select {
	case s.wake <- struct{}{}:
	default:
	}
	return nil
}

// Running starts the owned worker and waits for the latest startup export.
// It must be called from a running hook; an export failure is logged so the
// existing startup errorcheck remains responsible for the process exit.
func (s *StaticViewer) Running(ctx context.Context) error {
	_, _, err := s.start(ctx)
	return err
}

func (s *StaticViewer) start(ctx context.Context) (context.Context, bool, error) {
	s.mu.Lock()
	started := s.stopped != nil
	s.mu.Unlock()
	if started {
		return ctx, false, nil
	}
	failed := false
	next, err := addon.Concurrent(ctx, func(clean context.Context) error {
		s.master.mu.Lock()
		lifetime := s.master.lifetime
		s.master.mu.Unlock()
		if lifetime == nil {
			lifetime = clean
		}
		s.mu.Lock()
		if !s.closed && s.stopped == nil {
			life, cancel := context.WithCancel(lifetime)
			s.cancel, s.stopped = cancel, make(chan struct{})
			go s.run(life)
		}
		s.mu.Unlock()
		// Frontend Shutdown cancels the worker and this wait, but not the base
		// lifecycle context needed by Concurrent to reacquire dispatch normally.
		// Export failures are already logged for startup errorcheck.
		failed = s.Wait(lifetime) != nil
		return clean.Err()
	})
	return next, failed, err
}

// Wait observes the latest captured request, including any superseding request.
// Call it outside dispatch after Running has started the worker. It returns the
// export error or ctx.Err; neither implies an option rollback or process exit.
func (s *StaticViewer) Wait(ctx context.Context) error {
	for {
		s.mu.Lock()
		job := s.latest
		s.mu.Unlock()
		if job == nil {
			return nil
		}
		select {
		case <-job.done:
		case <-ctx.Done():
			return ctx.Err()
		}
		s.mu.Lock()
		if job == s.latest {
			err := job.err
			s.mu.Unlock()
			return err
		}
		s.mu.Unlock()
	}
}

func (s *StaticViewer) run(ctx context.Context) {
	defer close(s.stopped)
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
		}
		for {
			s.mu.Lock()
			job := s.pending
			s.pending = nil
			if job == nil {
				s.mu.Unlock()
				break
			}
			life, cancel := context.WithCancel(ctx)
			s.activeCancel = cancel
			s.mu.Unlock()
			err := exportViewerFile(life, job.input)
			cancel()
			s.mu.Lock()
			s.activeCancel = nil
			if err == nil {
				if s.published == nil {
					s.published = make(map[viewerInput]bool)
				}
				s.published[job.input] = true
			}
			shouldLog := err != nil && job == s.latest && ctx.Err() == nil && !errors.Is(err, context.Canceled)
			s.mu.Unlock()
			if shouldLog {
				s.master.logger.ErrorContext(ctx, "Static viewer export failed", "error", err)
			}
			s.mu.Lock()
			job.err = err
			close(job.done)
			s.mu.Unlock()
		}
	}
}

func (s *StaticViewer) close(ctx context.Context) error {
	s.mu.Lock()
	s.closed = true
	if s.cancel != nil {
		s.cancel()
	}
	if s.pending != nil {
		s.pending.err = context.Canceled
		close(s.pending.done)
		s.pending = nil
	}
	done := s.stopped
	s.mu.Unlock()
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func expandViewerPath(name string) (string, error) {
	if name == "~" || strings.HasPrefix(name, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		name = filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(name, "~"), "/"))
	}
	return filepath.Abs(name)
}

func exportViewerFile(ctx context.Context, input viewerInput) (err error) {
	if input.rfile == "" || input.rfile == "-" {
		return errors.New("static viewer requires a flow file path")
	}
	name, err := expandViewerPath(input.rfile)
	if err != nil {
		return err
	}
	file, err := os.Open(name) //nolint:gosec // Read the explicit rfile input, not a path derived from exported flow data.
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	var flows []flow.Flow
	for f, readErr := range flowio.NewReader(file).All() {
		if readErr != nil {
			return readErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		flows = append(flows, f)
	}
	return exportViewer(ctx, input.destination, flows, input.definitions)
}

func exportViewer(ctx context.Context, destination string, flows []flow.Flow, definitions string) (err error) {
	files, err := viewerFiles(ctx, flows, definitions)
	if err != nil {
		return err
	}
	export, err := newViewerExport(destination, files)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, export.close()) }()
	if err := export.write(ctx, files); err != nil {
		return err
	}
	return export.publish(ctx, files)
}

func viewerJSON(value any) ([]byte, error) {
	return json.Marshal(value, jsontext.SpaceAfterColon(true), jsontext.SpaceAfterComma(true))
}

func viewerStaticFiles() (map[string][]byte, error) {
	files := make(map[string][]byte)
	entries, err := assets.ReadDir("static")
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		name := "static/" + entry.Name()
		body, err := assets.ReadFile(name)
		if err != nil {
			return nil, err
		}
		files[name] = body
	}
	for name, target := range map[string]string{"index.html": "index.html", "UPSTREAM_LICENSE": "static/UPSTREAM_LICENSE"} {
		body, err := assets.ReadFile(name)
		if err != nil {
			return nil, err
		}
		files[target] = body
	}
	files["static/static.js"] = []byte("MITMWEB_STATIC = true;")
	return files, nil
}

func viewerFiles(ctx context.Context, flows []flow.Flow, definitions string) (map[string][]byte, error) {
	files, err := viewerStaticFiles()
	if err != nil {
		return nil, err
	}
	files["filter-help.json"], err = viewerJSON(struct {
		Commands []filter.HelpEntry `json:"commands"`
	}{filter.Help()})
	if err != nil {
		return nil, err
	}
	values := make([]any, 0, len(flows))
	for _, f := range flows {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		httpFlow, ok := f.(*flow.HTTPFlow)
		if !ok {
			return nil, errors.New("static viewer requires HTTP flows")
		}
		id, err := uuid.Parse(httpFlow.ID)
		if err != nil || id.String() != httpFlow.ID {
			return nil, errors.New("static viewer requires canonical flow IDs")
		}
		prefix := "flows/" + httpFlow.ID + "/"
		if _, exists := files[prefix+"request/content.data"]; exists {
			return nil, errors.New("static viewer contains duplicate flow IDs")
		}
		value, err := flowjson.Flow(f)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
		for _, part := range []string{"request", "response"} {
			var message *httpmsg.Message
			if part == "request" && httpFlow.Request != nil {
				message = &httpFlow.Request.Message
			}
			if part == "response" && httpFlow.Response != nil {
				message = &httpFlow.Response.Message
			}
			body := []byte("No content.")
			pretty := contentviews.Result{Text: "No content.", SyntaxHighlight: "none", ViewName: "/", Description: ""}
			if message != nil {
				if message.RawContent == nil {
					return nil, errors.New("static viewer cannot export missing message content")
				}
				body, err = message.Content()
				if err != nil {
					return nil, err
				}
				pretty = contentviews.PrettifyMessageWithMetadata(message, contentviews.Metadata{Flow: f, ProtobufDefinitions: definitions}, "auto", nil, 0)
			}
			files[prefix+part+"/content.data"] = body
			files[prefix+part+"/content/Auto.json"], err = viewerJSON(struct {
				Text            string `json:"text"`
				SyntaxHighlight string `json:"syntax_highlight"`
				ViewName        string `json:"view_name"`
				Description     string `json:"description"`
			}{pretty.Text, pretty.SyntaxHighlight, pretty.ViewName, pretty.Description})
			if err != nil {
				return nil, err
			}
		}
	}
	files["flows.json"], err = viewerJSON(values)
	return files, err
}

func (e *viewerExport) write(ctx context.Context, files map[string][]byte) error {
	// Replacement is confined to this invocation's private staging tree, never
	// to the visible destination or any caller-owned static subtree.
	if err := e.stage.RemoveAll("static"); err != nil {
		return err
	}
	return writeViewerFiles(ctx, e.stage, files)
}

func (e *viewerExport) saveSettings(ctx context.Context) error {
	body, err := viewerJSON(struct {
		Version string `json:"version"`
	}{version.Version})
	if err != nil {
		return err
	}
	return writeViewerFiles(ctx, e.stage, map[string][]byte{"settings.json": body})
}

func writeViewerFiles(ctx context.Context, root *os.Root, files map[string][]byte) error {
	for name, body := range files {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := root.MkdirAll(filepath.Dir(name), 0o700); err != nil {
			return err
		}
		file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		_, writeErr := file.Write(body)
		if err := errors.Join(writeErr, file.Close()); err != nil {
			return fmt.Errorf("write static viewer file: %w", err)
		}
	}
	return nil
}
