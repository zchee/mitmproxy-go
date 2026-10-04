// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package flowio

import (
	"io"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flowio/tnetstring"
)

// Writer writes flows to a flow file, porting mitmproxy's FlowWriter.
type Writer struct {
	w io.Writer
}

// NewWriter returns a Writer that writes flows to w.
func NewWriter(w io.Writer) *Writer {
	return &Writer{w: w}
}

// Add writes f in format [flow.FormatVersion]. Each flow is encoded in full
// before anything is written, so an encoding error writes nothing.
func (w *Writer) Add(f flow.Flow) error {
	b, err := tnetstring.Dumps(toTnetstring(f.GetState()))
	if err != nil {
		return err
	}
	_, err = w.w.Write(b)
	return err
}
