// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package addon runs addons: it registers them, and it dispatches hooks to
// them inside a single dispatch domain.
//
// # Dispatch domain
//
// mitmproxy runs every addon hook on one event loop, so addon state is only
// ever touched by one hook at a time. This package keeps that guarantee with
// one dispatch lock: a hook chain runs on the caller's goroutine while the
// lock is held.
//
// Go mutexes are not re-entrant, so the code that holds the lock passes a
// dispatch frame down in its [context.Context]. A call that finds a valid
// frame in its context (a command calling back into the hooks, an option
// change firing configure) runs inside the caller's hold of the lock instead
// of taking it again. A frame is valid only until the lock is released: the
// dispatcher's epoch advances on every release, and a frame records the
// epoch it was issued in. A goroutine that keeps a frame past that point,
// such as one started inside a hook, is caught the next time it presents the
// frame: test binaries panic, and other builds get [ErrStaleFrame].
//
// Only the goroutine that holds the lock may use its frame. The epoch check
// catches a frame used after the release; it cannot catch another goroutine
// using the frame while the hook that issued it is still running.
package addon

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

var (
	// ErrStaleFrame reports a context whose dispatch frame was issued before
	// the dispatch lock was last released.
	ErrStaleFrame = errors.New("addon: dispatch frame used after the dispatch lock was released")

	// ErrSyncContext reports a call to [Concurrent] from a nested dispatch,
	// from a hook mitmproxy dispatches synchronously (load, configure, and
	// the done of a removal) or from a command, where releasing the lock
	// would let other hooks run in the middle of the outer one.
	ErrSyncContext = errors.New("cannot be called from sync context")

	// ErrNoDispatch reports a call to [Concurrent] with a context that does
	// not come from a hook.
	ErrNoDispatch = errors.New("addon: not called from inside a hook")
)

// panicOnStaleFrame selects how a stale frame is reported. Test binaries
// panic so that the misuse cannot go unnoticed; tests of the error path turn
// it off.
var panicOnStaleFrame = testing.Testing()

// frame is the token that proves its holder runs under the dispatch lock.
// Its fields never change after it is issued.
type frame struct {
	d     *dispatcher
	epoch uint64
	depth int // 1 for the hold of the lock, plus one per re-entry
	// sync describes the synchronous dispatch the frame was issued for,
	// such as "load hook" or "command view.flows.add", and is inherited by
	// the frames re-entered from it; it is empty for an ordinary dispatch.
	// [Concurrent] refuses a frame that has it.
	sync string
}

type frameKey struct{}

// withFrame returns ctx carrying f. A nil f hides any frame ctx carries.
func withFrame(ctx context.Context, f *frame) context.Context {
	return context.WithValue(ctx, frameKey{}, f)
}

// frameFrom returns the frame ctx carries, or nil.
func frameFrom(ctx context.Context) *frame {
	if ctx == nil {
		return nil
	}
	f, _ := ctx.Value(frameKey{}).(*frame)
	return f
}

// dispatcher owns the dispatch lock and the frames issued under it.
type dispatcher struct {
	mu sync.Mutex
	// epoch counts releases of mu. It is advanced while mu is still held,
	// and read without mu by validity checks.
	epoch atomic.Uint64
	// cur is the outermost frame of the current hold of mu; nil while mu is
	// free. Only accessed with mu held. [Concurrent] replaces it, so a hook
	// chain picks it up again for each addon it calls.
	cur *frame

	// onStart and onEnd, when set, are called every time mu is acquired
	// and just before it is released. The proxy uses them to pause a
	// connection's idle watchdog while hooks run.
	onStart func()
	onEnd   func()
}

// valid reports whether f was issued in the current hold of the lock.
func (d *dispatcher) valid(f *frame) bool {
	return f.epoch == d.epoch.Load()
}

// stale reports the use of a stale frame.
func stale(f *frame) error {
	err := fmt.Errorf("%w (frame epoch %d, current epoch %d)", ErrStaleFrame, f.epoch, f.d.epoch.Load())
	if panicOnStaleFrame {
		panic(err)
	}
	return err
}

// acquire takes the lock and issues the outermost frame of the hold.
func (d *dispatcher) acquire() *frame {
	d.mu.Lock()
	if d.onStart != nil {
		d.onStart()
	}
	f := &frame{d: d, epoch: d.epoch.Load(), depth: 1}
	d.cur = f
	return f
}

// release makes every frame of the current hold stale, then releases the
// lock. The epoch advances before the unlock so that the next holder's
// frame is issued in the new epoch.
func (d *dispatcher) release() {
	d.cur = nil
	d.epoch.Add(1)
	if d.onEnd != nil {
		d.onEnd()
	}
	d.mu.Unlock()
}

// enter returns a frame to run under the dispatch lock with, and the
// function that ends the use of it, which the caller must defer.
//
// A valid frame of d in ctx is re-entered: the returned frame is one level
// deeper and nothing is locked. A frame of another dispatcher is ignored.
// Without a frame, enter waits for the lock.
func (d *dispatcher) enter(ctx context.Context) (*frame, func(), error) {
	if f := frameFrom(ctx); f != nil && f.d == d {
		if !d.valid(f) {
			return nil, nil, stale(f)
		}
		return &frame{d: d, epoch: f.epoch, depth: f.depth + 1, sync: f.sync}, func() {}, nil
	}
	return d.acquire(), d.release, nil
}

// inSync returns ctx with its frame replaced by one that marks a
// synchronous dispatch, described by what, in which [Concurrent] is
// refused. ctx must carry a valid frame.
func inSync(ctx context.Context, what string) context.Context {
	f := frameFrom(ctx)
	return withFrame(ctx, &frame{d: f.d, epoch: f.epoch, depth: f.depth, sync: what})
}

// current returns the frame to call the next addon of a chain with: the
// chain's own frame when it is nested or synchronous, otherwise the
// outermost frame of the hold, which [Concurrent] may have replaced since
// the chain started. A synchronous chain keeps its own frame because
// Concurrent cannot run in it. It must be called with the lock held.
func (d *dispatcher) current(f *frame) *frame {
	if f.depth == 1 && f.sync == "" {
		return d.cur
	}
	return f
}

// do runs fn under the dispatch lock, re-entering through a valid frame in
// ctx instead of locking again.
func (d *dispatcher) do(ctx context.Context, fn func(context.Context) error) error {
	f, exit, err := d.enter(ctx)
	if err != nil {
		return err
	}
	defer exit()
	return fn(withFrame(ctx, f))
}

// Concurrent runs fn with the dispatch lock released, so that hooks of other
// flows can run while fn blocks, for example on network I/O. The hook that
// calls it waits for fn and then holds the lock again.
//
// ctx must be the context the hook was called with, at the outermost level
// of dispatch: from a hook that was itself reached through another hook or a
// command, Concurrent returns an error wrapping [ErrSyncContext], because
// releasing the lock there would interleave other hooks with the outer one.
// It refuses the same way in the hooks mitmproxy dispatches synchronously:
// load, configure fired by an option change, and done fired by
// [Manager.Remove] or [Manager.Clear]. Releasing the lock there would let
// another registration, removal or option change run in the middle of this
// one. The done hook fired through [Manager.Trigger] at shutdown may call
// Concurrent. A command run through [Manager.Call] refuses it too, because
// a mitmproxy command is a synchronous call that cannot yield.
//
// fn gets a context without a dispatch frame; it must not touch addon state
// except through calls that take the lock themselves. Releasing the lock
// makes every frame issued so far stale, including the one in ctx: the hook
// must continue with the returned context, which carries a fresh frame.
//
// The fresh frame is a new value rather than the old frame made valid
// again, because the old frame may have been copied while the hook ran:
// a goroutine the hook started before calling Concurrent holds the same
// pointer, and refreshing that frame in place would make the goroutine's
// context pass the epoch check while the hook again holds the lock. The
// goroutine could then run addon code concurrently with the hook. A new
// frame reaches only the code the hook hands the returned context to.
func Concurrent(ctx context.Context, fn func(context.Context) error) (context.Context, error) {
	f := frameFrom(ctx)
	if f == nil {
		return ctx, ErrNoDispatch
	}
	d := f.d
	if !d.valid(f) {
		return ctx, stale(f)
	}
	if f.sync != "" {
		return ctx, fmt.Errorf("addon.Concurrent %w (%s)", ErrSyncContext, f.sync)
	}
	if f.depth > 1 {
		return ctx, fmt.Errorf("addon.Concurrent %w (dispatch depth %d)", ErrSyncContext, f.depth)
	}

	var (
		nf  *frame
		err error
	)
	d.release()
	func() {
		// Take the lock back even when fn panics, so that the hook's own
		// deferred release finds it held.
		defer func() { nf = d.acquire() }()
		err = fn(withFrame(ctx, nil))
	}()
	return withFrame(ctx, nf), err
}
