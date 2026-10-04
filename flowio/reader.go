// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package flowio reads and writes mitmproxy flow files.
//
// A flow file is a sequence of tnetstring dictionaries, one per flow, each
// holding a flow's state as [flow.Flow.GetState] returns it. [Reader]
// migrates flows written in formats 18 to 20 to the current format, as
// mitmproxy's FlowReader does, and [Writer] always writes the current
// format, byte for byte as mitmproxy's FlowWriter writes it.
package flowio

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"iter"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flow/state"
	"github.com/zchee/mitmproxy-go/flowio/tnetstring"
)

// ErrHARNotSupportedYet is returned by [Reader] for a HAR file, which
// mitmproxy also accepts as a flow file. HAR import is not implemented yet.
var ErrHARNotSupportedYet = errors.New("flowio: reading HAR files is not supported yet")

// utf8BOM is the byte order mark some tools, such as Fiddler, put before a
// HAR file.
const utf8BOM = "\xef\xbb\xbf"

// Reader reads flows from a flow file, porting mitmproxy's FlowReader.
type Reader struct {
	r       *bufio.Reader
	started bool
	err     error
}

// NewReader returns a Reader that reads flows from r. It buffers r unless r
// already is a *bufio.Reader.
func NewReader(r io.Reader) *Reader {
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReader(r)
	}
	return &Reader{r: br}
}

// Next returns the next flow. It returns io.EOF after the last flow. Once
// Next has returned an error, it returns the same error on every later
// call.
//
// A flow in a format older than [flow.FormatVersion] is migrated first; a
// format that cannot be read is reported as a *[VersionError]. Errors from
// the tnetstring codec and from the flow models are returned unwrapped, so
// their messages read like mitmproxy's.
func (r *Reader) Next() (flow.Flow, error) {
	if r.err != nil {
		return nil, r.err
	}
	f, err := r.next()
	if err != nil {
		r.err = err
	}
	return f, err
}

func (r *Reader) next() (flow.Flow, error) {
	if !r.started {
		r.started = true
		if p, _ := r.r.Peek(len(utf8BOM) + 1); bytes.Equal(p, []byte(utf8BOM+"{")) {
			if _, err := r.r.Discard(len(utf8BOM)); err != nil {
				return nil, err
			}
		}
		if p, _ := r.r.Peek(1); bytes.Equal(p, []byte("{")) {
			return nil, ErrHARNotSupportedYet
		}
	}

	v, err := tnetstring.Load(r.r)
	if err != nil {
		return nil, err
	}
	d, ok := v.(*tnetstring.Dict)
	if !ok {
		return nil, fmt.Errorf("invalid flow: the top-level value is a %s, not a dict", state.TypeName(v))
	}
	m := fromTnetstring(d).(*state.Map)
	if err := migrate(m); err != nil {
		return nil, err
	}
	return flow.FromState(m)
}

// All returns an iterator over the remaining flows, as mitmproxy's
// FlowReader.stream does. It stops after the last flow, or after yielding
// the first error with a nil flow.
func (r *Reader) All() iter.Seq2[flow.Flow, error] {
	return func(yield func(flow.Flow, error) bool) {
		for {
			f, err := r.Next()
			if errors.Is(err, io.EOF) {
				return
			}
			if !yield(f, err) || err != nil {
				return
			}
		}
	}
}
