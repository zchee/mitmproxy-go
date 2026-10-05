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
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"iter"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flow/state"
	"github.com/zchee/mitmproxy-go/flowio/har"
	"github.com/zchee/mitmproxy-go/flowio/tnetstring"
)

type harReadError struct{ err error }

func (e *harReadError) Error() string {
	return "Unable to read HAR file. Please provide a valid HAR file"
}
func (e *harReadError) Unwrap() error { return e.err }

// utf8BOM is the byte order mark some tools, such as Fiddler, put before a
// HAR file.
const utf8BOM = "\xef\xbb\xbf"

// Reader reads flows from a flow file, porting mitmproxy's FlowReader.
// Files starting with {, optionally immediately preceded by a UTF-8 BOM, are
// HAR documents, limited to 256 MiB and 1000 nested objects or arrays.
type Reader struct {
	r       *bufio.Reader
	started bool
	err     error
	harMode bool
	entries []jsontext.Value
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
			r.harMode = true
			entries, err := har.ReadEntries(r.r)
			if err != nil {
				return nil, &harReadError{err}
			}
			r.entries = entries
		}
	}

	if r.harMode {
		if len(r.entries) == 0 {
			return nil, io.EOF
		}
		entry := r.entries[0]
		r.entries[0] = nil
		r.entries = r.entries[1:]
		f, err := har.RequestToFlow(entry)
		if err != nil {
			return nil, &harReadError{err}
		}
		return f, nil
	}

	v, err := tnetstring.Load(r.r)
	if err != nil {
		return nil, err
	}
	m, ok := v.(*state.Map)
	if !ok {
		return nil, fmt.Errorf("invalid flow: the top-level value is a %s, not a dict", state.TypeName(v))
	}
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
