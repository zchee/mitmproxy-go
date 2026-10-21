// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build consolestorm && linux

package acceptance_test

import (
	"context"
	"crypto/sha256"
	json "encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/colorprofile"
	"github.com/charmbracelet/x/ansi"
	gocmp "github.com/google/go-cmp/cmp"
	"go.uber.org/goleak"
	"golang.org/x/sys/unix"

	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/internal/tools/console"
	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
	"github.com/zchee/mitmproxy-go/options"
)

type stormReceipt struct {
	ChildArgv             []string `json:"child_argv"`
	ChildCPU              string   `json:"child_cpu"`
	ChildGOMAXPROCS       int      `json:"child_gomaxprocs"`
	ProducedIDs           []string `json:"produced_ids"`
	PresentedIDs          []string `json:"presented_ids"`
	EntryNS               int64    `json:"entry_ns"`
	ProductionNS          int64    `json:"production_ns"`
	ReleaseNS             int64    `json:"release_ns"`
	DeliveryNS            int64    `json:"delivery_ns"`
	DispatchNS            int64    `json:"dispatch_ns"`
	BlockNS               int64    `json:"block_ns"`
	ProducedAtRelease     int64    `json:"produced_at_release"`
	EntryGeneration       uint64   `json:"entry_generation"`
	FinalGeneration       uint64   `json:"final_generation"`
	SnapshotSendHighWater int64    `json:"snapshot_send_high_water"`
	SnapshotSends         int64    `json:"snapshot_sends"`
	OutstandingHighWater  int64    `json:"outstanding_snapshot_high_water"`
	WakeCapacity          int      `json:"wake_capacity"`
	WakeProof             string   `json:"wake_proof"`
	DeliveredSnapshots    int      `json:"delivered_snapshots"`
	StoreCount            int      `json:"store_count"`
	ListCount             int      `json:"list_count"`
	Navigation            []string `json:"navigation"`
	Joined                bool     `json:"joined"`
	Passed                bool     `json:"passed"`
}

type stormFrame struct {
	snapshot    contract.Snapshot
	text        string
	deliveredNS int64
}

type stormQuery struct{ reply chan stormFrame }

type stormModel struct {
	model           *console.Model
	epoch           time.Time
	entered         chan struct{}
	changed         chan struct{}
	once            sync.Once
	produced        atomic.Int64
	entryNS         atomic.Int64
	releaseNS       atomic.Int64
	atRelease       atomic.Int64
	entryGeneration uint64
	last            contract.Snapshot
	deliveries      int
	deliveredNS     int64
	outstanding     atomic.Int64
	outstandingMax  atomic.Int64
}

func (m *stormModel) Init() tea.Cmd  { return m.model.Init() }
func (m *stormModel) View() tea.View { return m.model.View() }
func (m *stormModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if query, ok := msg.(stormQuery); ok {
		query.reply <- stormFrame{snapshot: m.last.Clone(), text: ansi.Strip(m.View().Content), deliveredNS: m.deliveredNS}
		return m, nil
	}
	if snapshot, ok := msg.(contract.SnapshotMsg); ok {
		m.once.Do(func() {
			m.entryGeneration = snapshot.Snapshot.Generation
			m.entryNS.Store(time.Since(m.epoch).Nanoseconds())
			timer := time.NewTimer(2 * time.Second)
			defer timer.Stop()
			close(m.entered)
			<-timer.C
			m.atRelease.Store(m.produced.Load())
			m.releaseNS.Store(time.Since(m.epoch).Nanoseconds())
		})
	}
	_, cmd := m.model.Update(msg)
	if snapshot, ok := msg.(contract.SnapshotMsg); ok {
		m.last = snapshot.Snapshot.Clone()
		m.deliveries++
		m.deliveredNS = time.Since(m.epoch).Nanoseconds()
		m.outstanding.Add(-1)
	}
	select {
	case m.changed <- struct{}{}:
	default:
	}
	return m, cmd
}

func TestArtifactRootSymlink(t *testing.T) {
	root := t.TempDir()
	link := filepath.Join(t.TempDir(), "artifacts")
	requireNoError(t, os.Symlink(root, link))
	t.Setenv("MITMPROXY_TEST_CONSOLE_ARTIFACTS", link)
	out := consoleArtifactDir(t, "symlink-")
	canonical, err := filepath.EvalSymlinks(root)
	requireNoError(t, err)
	if diff := gocmp.Diff(canonical, filepath.Dir(out)); diff != "" {
		t.Fatalf("symlink artifact parent (-want +got):\n%s", diff)
	}
}

func TestConsoleStorm(t *testing.T) {
	tests := map[string]struct{}{"update_blocked_two_seconds": {}}
	for name := range tests {
		t.Run(name, func(t *testing.T) {
			if os.Getenv("MITMPROXY_CONSOLE_STORM_HELPER") == "1" {
				runStormHelper(t)
				return
			}
			runStormProcess(t)
		})
	}
}

func closeStormFile(t *testing.T, file *os.File) {
	t.Helper()
	if err := file.Close(); !errors.Is(err, os.ErrClosed) {
		requireNoError(t, err)
	}
}

func runStormProcess(t *testing.T) {
	t.Helper()
	masterFD, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	requireNoError(t, err)
	terminal := os.NewFile(uintptr(masterFD), "console-storm-pty")
	defer closeStormFile(t, terminal)
	requireNoError(t, unix.IoctlSetPointerInt(masterFD, unix.TIOCSPTLCK, 0))
	number, err := unix.IoctlGetInt(masterFD, unix.TIOCGPTN)
	requireNoError(t, err)
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|syscall.O_NOCTTY, 0)
	requireNoError(t, err)
	defer closeStormFile(t, slave)
	requireNoError(t, unix.IoctlSetWinsize(masterFD, unix.TIOCSWINSZ, &unix.Winsize{Col: 80, Row: 24}))
	reportReader, reportWriter, err := os.Pipe()
	requireNoError(t, err)
	defer closeStormFile(t, reportReader)
	defer closeStormFile(t, reportWriter)
	executable, err := os.Executable()
	requireNoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestConsoleStorm$/^update_blocked_two_seconds$", "-test.count=1", "-test.cpu=1", "-test.timeout=40s", "-test.v") //nolint:gosec // Re-executes this exact test binary with a fixed selector.
	cmd.Env = append(os.Environ(), "MITMPROXY_CONSOLE_STORM_HELPER=1", "TERM=xterm-256color", "TZ=UTC")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.ExtraFiles = []*os.File{reportWriter}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0, Pdeathsig: syscall.SIGKILL}
	cmd.Cancel = func() error {
		err := unix.Kill(-cmd.Process.Pid, unix.SIGKILL)
		if errors.Is(err, unix.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	out := consoleArtifactDir(t, "storm-")
	transcript, err := os.OpenFile(filepath.Join(out, "terminal.ansi"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	requireNoError(t, err)
	defer closeStormFile(t, transcript)
	requireNoError(t, cmd.Start())
	pid := cmd.Process.Pid
	defer func() {
		if cmd.ProcessState == nil {
			_ = unix.Kill(-pid, unix.SIGKILL)
			_ = cmd.Wait()
		}
	}()
	requireNoError(t, slave.Close())
	requireNoError(t, reportWriter.Close())
	terminalDone := make(chan error, 1)
	go func() {
		_, err := io.Copy(transcript, terminal)
		if errors.Is(err, unix.EIO) {
			err = nil // Linux reports EIO when the last slave descriptor closes.
		}
		terminalDone <- err
	}()
	reportDone := make(chan struct {
		data []byte
		err  error
	}, 1)
	go func() {
		data, err := io.ReadAll(io.LimitReader(reportReader, 4<<20))
		reportDone <- struct {
			data []byte
			err  error
		}{data, err}
	}()
	waitErr := cmd.Wait()
	var data []byte
	select {
	case report := <-reportDone:
		requireNoError(t, report.err)
		data = report.data
	case <-ctx.Done():
		t.Fatalf("owned helper report pipe did not close: %v; artifacts=%s", ctx.Err(), out)
	}
	requireNoError(t, os.WriteFile(filepath.Join(out, "helper.json"), data, 0o600))
	select {
	case err := <-terminalDone:
		requireNoError(t, err)
	case <-ctx.Done():
		t.Fatalf("PTY reader survived reaped helper: %v; artifacts=%s", ctx.Err(), out)
	}
	if err := unix.Kill(-pid, 0); !errors.Is(err, unix.ESRCH) {
		t.Fatalf("owned helper process group %d survived Wait: %v", pid, err)
	}
	if waitErr != nil {
		t.Fatalf("owned PTY helper failed: %v; receipt and terminal transcript: %s", waitErr, out)
	}
	var receipt stormReceipt
	requireNoError(t, json.Unmarshal(data, &receipt, json.RejectUnknownMembers(true)))
	if receipt.ChildCPU != "1" || receipt.ChildGOMAXPROCS != 1 || !slices.Equal(receipt.ChildArgv, cmd.Args) {
		t.Fatalf("child CPU profile or argv differs: cpu=%q GOMAXPROCS=%d argv=%q; artifacts=%s", receipt.ChildCPU, receipt.ChildGOMAXPROCS, receipt.ChildArgv, out)
	}
	if !receipt.Passed || !receipt.Joined || receipt.ProducedAtRelease != 10_000 || receipt.ProductionNS >= receipt.ReleaseNS || receipt.BlockNS < int64(2*time.Second) {
		t.Fatalf("helper violated fixed hold/count/join contract: %+v; artifacts=%s", receipt, out)
	}
	if diff := gocmp.Diff(receipt.ProducedIDs, receipt.PresentedIDs); diff != "" {
		t.Fatalf("owned helper lost IDs/order (-produced +presented):\n%s", diff)
	}
	t.Logf("PTY helper pid=%d reaped; process group absent; produced=%d list=%d store=%d entry_ns=%d production_ns=%d release_ns=%d delivery_ns=%d block_ns=%d dispatch_ns=%d send_high_water=%d artifacts=%s", pid, len(receipt.ProducedIDs), receipt.ListCount, receipt.StoreCount, receipt.EntryNS, receipt.ProductionNS, receipt.ReleaseNS, receipt.DeliveryNS, receipt.BlockNS, receipt.DispatchNS, receipt.SnapshotSendHighWater, out)
}

func runStormHelper(t *testing.T) {
	t.Helper()
	receipt := stormReceipt{ChildArgv: slices.Clone(os.Args), ChildGOMAXPROCS: runtime.GOMAXPROCS(0)}
	if cpu := flag.Lookup("test.cpu"); cpu != nil {
		receipt.ChildCPU = cpu.Value.String()
	}
	report := os.NewFile(3, "console-storm-report")
	defer func() {
		data, err := json.Marshal(receipt)
		requireNoError(t, err)
		_, err = report.Write(data)
		requireNoError(t, err)
		requireNoError(t, report.Close())
	}()
	ctx, cancel := context.WithCancel(context.WithoutCancel(t.Context()))
	defer cancel()
	opts := options.New()
	requireNoError(t, opts.Update(ctx, map[string]any{"confdir": t.TempDir(), "server": false}))
	master, err := console.New(ctx, console.Config{Options: opts, Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr})
	requireNoError(t, err)
	defer func() { requireNoError(t, master.Close(context.WithoutCancel(t.Context()))) }()
	model, err := master.NewModel()
	requireNoError(t, err)
	observed := &stormModel{model: model, epoch: time.Now(), entered: make(chan struct{}), changed: make(chan struct{}, 1)}
	program := tea.NewProgram(observed, tea.WithContext(context.WithoutCancel(master.Bridge.Context())), tea.WithInput(os.Stdin), tea.WithOutput(os.Stdout), tea.WithWindowSize(80, 24), tea.WithColorProfile(colorprofile.TrueColor), tea.WithoutSignals())
	programDone, masterDone := make(chan error, 1), make(chan error, 1)
	snapshotDone, effectsDone := make(chan struct{}), make(chan struct{})
	go func() { _, err := program.Run(); programDone <- err }()
	go func() { masterDone <- master.Run(ctx) }()
	joined := false
	join := func() {
		if joined {
			return
		}
		joined = true
		program.Quit()
		select {
		case err := <-programDone:
			requireNoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("real PTY program failed orderly Quit")
		}
		master.Shutdown()
		select {
		case err := <-masterDone:
			requireNoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("storm master lifecycle did not join")
		}
		for _, done := range []<-chan struct{}{snapshotDone, effectsDone} {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("storm bridge sender survived shutdown")
			}
		}
		receipt.Joined = true
	}
	select {
	case <-master.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("PTY model did not acknowledge Init")
	}
	var activeSends, highWater, sends atomic.Int64
	defer func() {
		receipt.EntryNS, receipt.ReleaseNS = observed.entryNS.Load(), observed.releaseNS.Load()
		if receipt.EntryNS > 0 && receipt.ReleaseNS > 0 {
			receipt.BlockNS = receipt.ReleaseNS - receipt.EntryNS
		}
		receipt.ProducedAtRelease = observed.atRelease.Load()
		receipt.SnapshotSendHighWater, receipt.SnapshotSends = highWater.Load(), sends.Load()
		receipt.OutstandingHighWater = observed.outstandingMax.Load()
		receipt.WakeCapacity = 1
		receipt.WakeProof = "wake capacity is 1 by design with a nonblocking send; internal/tools/console TestConsoleBridge/deterministic/{dirty_race,saturated_no_state_change,update_blocked} proves coalescing"
		// Presentation-owned fields are read only after the UI and senders have joined.
		if receipt.Joined {
			receipt.EntryGeneration, receipt.FinalGeneration = observed.entryGeneration, observed.last.Generation
			receipt.DeliveryNS = observed.deliveredNS
			receipt.DeliveredSnapshots = observed.deliveries
			receipt.StoreCount, receipt.ListCount = observed.last.StoreCount, observed.last.Total
			receipt.PresentedIDs = slices.Clone(observed.last.IDs)
		}
	}()
	go func() {
		defer close(snapshotDone)
		master.Bridge.DrainTo(func(msg tea.Msg) {
			pending := activeSends.Add(1)
			for {
				prior := highWater.Load()
				if pending <= prior || highWater.CompareAndSwap(prior, pending) {
					break
				}
			}
			sends.Add(1)
			outstanding := observed.outstanding.Add(1)
			for {
				prior := observed.outstandingMax.Load()
				if outstanding <= prior || observed.outstandingMax.CompareAndSwap(prior, outstanding) {
					break
				}
			}
			program.Send(msg)
			activeSends.Add(-1)
		})()
	}()
	go func() { defer close(effectsDone); master.Bridge.DeliverEffectsTo(program.Send)() }()
	defer join()
	select {
	case <-observed.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("actual Update did not acknowledge timed hold entry")
	}
	probe := make(chan error, 1)
	go func() {
		err := master.Do(ctx, func(context.Context) error { receipt.DispatchNS = time.Since(observed.epoch).Nanoseconds(); return nil })
		probe <- err
	}()
	for index := range 10_000 {
		f := testflow.TFlow()
		f.Live = false
		f.Request.TimestampStart = float64(index + 1)
		f.Request.Path = fmt.Sprintf("/storm/%05d", index)
		receipt.ProducedIDs = append(receipt.ProducedIDs, f.ID)
		requireNoError(t, master.LoadFlow(ctx, f))
		observed.produced.Add(1)
	}
	receipt.ProductionNS = time.Since(observed.epoch).Nanoseconds()
	requireNoError(t, <-probe)
	frame := waitStormFrame(t, program, observed, func(frame stormFrame) bool {
		return frame.snapshot.Total == 10_000 && strings.Contains(frame.text, "[1/10000]")
	})
	receipt.EntryNS, receipt.ReleaseNS = observed.entryNS.Load(), observed.releaseNS.Load()
	receipt.BlockNS = receipt.ReleaseNS - receipt.EntryNS
	receipt.ProducedAtRelease = observed.atRelease.Load()
	receipt.DeliveryNS = frame.deliveredNS
	receipt.EntryGeneration, receipt.FinalGeneration = observed.entryGeneration, frame.snapshot.Generation
	receipt.SnapshotSendHighWater, receipt.SnapshotSends = highWater.Load(), sends.Load()
	receipt.StoreCount, receipt.ListCount = frame.snapshot.StoreCount, frame.snapshot.Total
	receipt.PresentedIDs = slices.Clone(frame.snapshot.IDs)
	if receipt.ProducedAtRelease != 10_000 || receipt.ProductionNS >= receipt.ReleaseNS || receipt.DispatchNS >= receipt.ReleaseNS {
		t.Fatalf("10,000 hooks and independent dispatch did not finish during fixed hold: produced=%d entry=%d production=%d release=%d dispatch=%d", receipt.ProducedAtRelease, receipt.EntryNS, receipt.ProductionNS, receipt.ReleaseNS, receipt.DispatchNS)
	}
	if receipt.StoreCount != 10_000 || receipt.ListCount != 10_000 || !slices.Equal(receipt.ProducedIDs, receipt.PresentedIDs) {
		t.Fatal("released snapshot lost real loaded flow membership/order")
	}
	unique := make(map[string]struct{}, len(receipt.ProducedIDs))
	for _, id := range receipt.ProducedIDs {
		unique[id] = struct{}{}
	}
	if len(unique) != 10_000 {
		t.Fatal("produced flow IDs are not distinct")
	}
	navigation := map[string]struct{ offset, index int }{"first": {0, 0}, "last": {-1, 9_999}, "deep": {5_678, 5_678}}
	for name, target := range navigation {
		_, err := master.Bridge.Call(ctx, "view.focus.go", target.offset)
		requireNoError(t, err)
		master.Bridge.RequestViewport(contract.Viewport{Offset: target.index, Width: 80, Height: 20})
		frame = waitStormFrame(t, program, observed, func(frame stormFrame) bool {
			return frame.snapshot.FocusIndex == target.index && frame.snapshot.FocusID == receipt.ProducedIDs[target.index] && strings.Contains(frame.text, fmt.Sprintf("/storm/%05d", target.index))
		})
		if !slices.Equal(receipt.ProducedIDs, frame.snapshot.IDs) {
			t.Fatalf("%s navigation changed complete presentation ID order", name)
		}
		receipt.Navigation = append(receipt.Navigation, name)
	}
	join()
	goleak.VerifyNone(t)
	receipt.Passed = !t.Failed()
	fingerprint := sha256.Sum256([]byte(strings.Join(receipt.PresentedIDs, "\n")))
	t.Logf("all 10000 presentation IDs and navigation verified, sha256=%x", fingerprint)
}

func waitStormFrame(t *testing.T, program *tea.Program, model *stormModel, ready func(stormFrame) bool) stormFrame {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	var last stormFrame
	for {
		reply := make(chan stormFrame, 1)
		program.Send(stormQuery{reply: reply})
		select {
		case last = <-reply:
			if ready(last) {
				return last
			}
		case <-ctx.Done():
			t.Fatalf("storm frame query timed out: %v", ctx.Err())
		}
		select {
		case <-model.changed:
		case <-ctx.Done():
			t.Fatalf("storm snapshot did not settle: %v total=%d focus=%d\n%s", ctx.Err(), last.snapshot.Total, last.snapshot.FocusIndex, last.text)
		}
	}
}
