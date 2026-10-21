// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package acceptance_test

import (
	"context"
	"crypto/sha256"
	json "encoding/json/v2"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/colorprofile"
	"github.com/charmbracelet/x/ansi"
	teatest "github.com/charmbracelet/x/exp/teatest/v2"
	gocmp "github.com/google/go-cmp/cmp"
	"go.uber.org/goleak"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flowio"
	"github.com/zchee/mitmproxy-go/internal/tools/console"
	"github.com/zchee/mitmproxy-go/options"
)

type frameInputs struct {
	FlowSHA256 string            `json:"flow_sha256"`
	IDs        []string          `json:"ids"`
	Options    []string          `json:"options"`
	States     map[string]string `json:"states"`
	Timezone   string            `json:"timezone"`
}

type frameObservation struct {
	view    tea.View
	pending int64
}

type (
	frameQuery    struct{ reply chan frameObservation }
	frameResponse struct{ message tea.Msg }
)

type frameModel struct {
	model   *console.Model
	changed chan struct{}
	pending atomic.Int64
}

func (m *frameModel) Init() tea.Cmd  { return m.track(m.model.Init()) }
func (m *frameModel) View() tea.View { return m.model.View() }
func (m *frameModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if query, ok := msg.(frameQuery); ok {
		query.reply <- frameObservation{view: m.View(), pending: m.pending.Load()}
		return m, nil
	}
	response, completed := msg.(frameResponse)
	if completed {
		msg = response.message
	}
	_, cmd := m.model.Update(msg)
	cmd = m.track(cmd)
	if completed {
		m.pending.Add(-1)
	}
	select {
	case m.changed <- struct{}{}:
	default:
	}
	return m, cmd
}

func (m *frameModel) track(cmd tea.Cmd) tea.Cmd {
	if cmd == nil {
		return nil
	}
	m.pending.Add(1)
	return func() tea.Msg {
		message := cmd()
		if batch, ok := message.(tea.BatchMsg); ok {
			for i := range batch {
				batch[i] = m.track(batch[i])
			}
			m.pending.Add(-1)
			return batch
		}
		return frameResponse{message: message}
	}
}

type runningProbe struct{ ready chan struct{} }

func (p *runningProbe) Running(context.Context) error { close(p.ready); return nil }

var (
	teatestConstructors atomic.Int64
	listenerWaitHeader  = regexp.MustCompile(`^goroutine [0-9]+ \[chan receive(?:, [0-9]+ minutes)?\]:$`)
)

func isSignalListener(block string) bool {
	header, _, _ := strings.Cut(block, "\n")
	return listenerWaitHeader.MatchString(header) &&
		strings.Contains(block, "github.com/charmbracelet/x/exp/teatest/v2.NewTestModel.func2()") &&
		strings.Contains(block, "teatest.go:168 ")
}

func signalListeners(t *testing.T) int64 {
	t.Helper()
	buffer := make([]byte, 4<<20)
	n := runtime.Stack(buffer, true)
	if n == len(buffer) {
		t.Fatal("goroutine inventory exceeded buffer")
	}
	var count int64
	for block := range strings.SplitSeq(string(buffer[:n]), "\n\n") {
		if !strings.Contains(block, "github.com/charmbracelet/x/exp/teatest/v2.NewTestModel.func2()") {
			continue
		}
		if !isSignalListener(block) {
			t.Fatalf("unexpected teatest listener function/wait site:\n%s", block)
		}
		count++
	}
	return count
}

func requireNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func resolveArtifactRoot(root string) (string, error) {
	if !filepath.IsAbs(root) {
		return "", fmt.Errorf("MITMPROXY_TEST_CONSOLE_ARTIFACTS must be an absolute path: %q", root)
	}
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("resolve console artifact root %q: %w", root, err)
	}
	info, err := os.Stat(canonical)
	if err != nil {
		return "", fmt.Errorf("stat console artifact root %q: %w", canonical, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("console artifact root %q must be an existing directory", canonical)
	}
	if err := checkArtifactRootOwner(info); err != nil {
		return "", fmt.Errorf("console artifact root %q: %w", canonical, err)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return "", fmt.Errorf("console artifact root %q must not be group- or other-writable", canonical)
	}
	return canonical, nil
}

func consoleArtifactDir(t *testing.T, prefix string) string {
	t.Helper()
	configured := os.Getenv("MITMPROXY_TEST_CONSOLE_ARTIFACTS")
	root := configured
	if root == "" {
		root = t.TempDir()
	}
	canonical, err := resolveArtifactRoot(root)
	if err != nil {
		t.Fatalf("MITMPROXY_TEST_CONSOLE_ARTIFACTS=%q: %v", configured, err)
	}
	out, err := os.MkdirTemp(canonical, prefix)
	requireNoError(t, err)
	t.Logf("console artifacts: configured=%q canonical=%q output=%q", configured, canonical, out)
	return out
}

func loadFrameInputs(t *testing.T) frameInputs {
	t.Helper()
	data, err := os.ReadFile("testdata/fixtures.json")
	requireNoError(t, err)
	var inputs frameInputs
	requireNoError(t, json.Unmarshal(data, &inputs, json.RejectUnknownMembers(false)))
	fixture, err := os.ReadFile("testdata/console.mitm")
	requireNoError(t, err)
	if got := fmt.Sprintf("%x", sha256.Sum256(fixture)); got != inputs.FlowSHA256 {
		t.Fatalf("shared fixture digest %s, want %s", got, inputs.FlowSHA256)
	}
	return inputs
}

func captureFrame(t *testing.T, state string, width, height int) (tea.View, []byte) {
	t.Helper()
	inputs := loadFrameInputs(t)
	t.Setenv("TZ", inputs.Timezone)
	ctx, cancel := context.WithCancel(context.WithoutCancel(t.Context()))
	defer cancel()
	opts := options.New()
	requireNoError(t, opts.Update(ctx, map[string]any{"confdir": t.TempDir(), "server": false}))
	master, err := console.New(ctx, console.Config{Options: opts, Stdout: io.Discard, Stderr: io.Discard})
	requireNoError(t, err)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
		defer stop()
		requireNoError(t, master.Close(cleanup))
	})
	requireNoError(t, opts.Set(ctx, inputs.Options...))
	model, err := master.NewModel()
	requireNoError(t, err)
	probe := &runningProbe{ready: make(chan struct{})}
	requireNoError(t, master.Addons.Add(ctx, probe))
	observed := &frameModel{model: model, changed: make(chan struct{}, 1)}
	before := signalListeners(t)
	if expected := teatestConstructors.Load(); before != expected {
		t.Fatalf("before constructor: SIGINT listener count %d, want exactly %d", before, expected)
	}
	terminal := teatest.NewTestModel(t, observed, teatest.WithInitialTermSize(width, height), teatest.WithProgramOptions(tea.WithContext(master.Bridge.Context()), tea.WithColorProfile(colorprofile.TrueColor)))
	constructors := teatestConstructors.Add(1)
	finished := make(chan error, 1)
	snapshotsDone, effectsDone := make(chan struct{}), make(chan struct{})
	go func() { defer close(snapshotsDone); master.Bridge.DrainTo(terminal.Send)() }()
	go func() { defer close(effectsDone); master.Bridge.DeliverEffectsTo(terminal.Send)() }()
	go func() { finished <- master.Run(ctx) }()
	joined := false
	join := func() {
		if joined {
			return
		}
		joined = true
		requireNoError(t, terminal.Quit())
		terminal.WaitFinished(t, teatest.WithFinalTimeout(5*time.Second))
		master.Shutdown()
		select {
		case err := <-finished:
			requireNoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("assembled master lifecycle did not join")
		}
		for _, done := range []<-chan struct{}{snapshotsDone, effectsDone} {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("owned snapshot/effect sender survived master shutdown")
			}
		}
	}
	defer join()
	select {
	case <-probe.ready:
	case err := <-finished:
		finished <- err
		t.Fatalf("assembled lifecycle failed before Running: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("assembled lifecycle did not reach Running")
	}
	file, err := os.Open("testdata/console.mitm")
	requireNoError(t, err)
	reader := flowio.NewReader(file)
	var ids []string
	for {
		f, err := reader.Next()
		if err == io.EOF {
			break
		}
		requireNoError(t, err)
		ids = append(ids, f.Common().ID)
		requireNoError(t, master.Do(t.Context(), func(ctx context.Context) error {
			master.View.Add(ctx, []flow.Flow{f})
			return nil
		}))
	}
	requireNoError(t, file.Close())
	if diff := gocmp.Diff(inputs.IDs, ids); diff != "" {
		t.Fatalf("shared fixture IDs (-want +got):\n%s", diff)
	}
	waitFrame(t, terminal, observed, func(v tea.View) bool {
		text := ansi.Strip(v.Content)
		return strings.Contains(text, "/inspect") && strings.Contains(text, "/paused") && strings.Contains(text, "Connection refused") && strings.Contains(text, "[1/3]")
	})
	keys, ok := inputs.States[state]
	if !ok {
		t.Fatalf("unknown frozen state %q", state)
	}
	switch keys {
	case "":
	case "<enter>":
		terminal.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	default:
		if !strings.HasPrefix(keys, ":") {
			t.Fatalf("unsupported frozen key sequence %q", keys)
		}
		terminal.Type(":")
		waitFrame(t, terminal, observed, func(v tea.View) bool {
			return strings.Contains(ansi.Strip(v.Content), ": ")
		})
		terminal.Type(strings.TrimPrefix(keys, ":"))
	}
	ack := waitFrame(t, terminal, observed, func(v tea.View) bool {
		text := ansi.Strip(v.Content)
		switch state {
		case "flowlist":
			return strings.Contains(text, "[1/3]") && strings.Contains(text, "Connection refused")
		case "flowview":
			return strings.Contains(text, "console request body") && strings.Contains(text, "content-type")
		case "commander":
			return strings.Contains(text, ": console.view.flow flow ")
		default:
			return false
		}
	})
	join()
	final := terminal.FinalModel(t, teatest.WithFinalTimeout(5*time.Second)).View()
	if diff := gocmp.Diff(ack.Content, final.Content); diff != "" {
		t.Fatalf("frame changed after synchronization acknowledgement (-ack +final):\n%s", diff)
	}
	transcript, err := io.ReadAll(terminal.FinalOutput(t))
	requireNoError(t, err)
	if got := signalListeners(t); got != constructors || got != before+1 {
		t.Fatalf("after joins: SIGINT listener count %d, want %d constructors; before=%d", got, constructors, before)
	}
	goleak.VerifyNone(t, goleak.IgnoreTopFunction("github.com/charmbracelet/x/exp/teatest/v2.NewTestModel.func2"))
	t.Logf("teatest SIGINT allowance: before=%d constructors=%d after=%d; owned lifecycle and both senders joined", before, constructors, signalListeners(t))
	return final, transcript
}

func waitFrame(t *testing.T, terminal *teatest.TestModel, model *frameModel, ready func(tea.View) bool) tea.View {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	var last tea.View
	for {
		reply := make(chan frameObservation, 1)
		terminal.Send(frameQuery{reply: reply})
		select {
		case observation := <-reply:
			last = observation.view
			if observation.pending == 0 && ready(last) {
				return last
			}
		case <-ctx.Done():
			t.Fatalf("frame acknowledgement timed out: %v", ctx.Err())
		}
		select {
		case <-model.changed:
		case <-ctx.Done():
			t.Fatalf("assembled frame did not settle: %v\n%s", ctx.Err(), ansi.Strip(last.Content))
		}
	}
}
