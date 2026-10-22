// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package script

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flow/state"
	"github.com/zchee/mitmproxy-go/httpmsg"
)

// Commands may retain arguments (replay.client queues its input). Each call owns
// a separate graph; only detached synchronous results return to the worker.
type commandOwnership struct {
	flows      map[flow.Flow]flow.Flow
	conversion conversion
	active     map[any]bool
}

func (o *commandOwnership) argument(value any, depth int) (any, error) {
	if err := o.conversion.admit(depth, 0); err != nil {
		return nil, err
	}
	var identity any
	switch v := value.(type) {
	case *state.Map:
		if v != nil {
			identity = v
		}
	case []any:
		if len(v) > 0 {
			identity = &v[0]
		}
	}
	if identity != nil {
		if o.active == nil {
			o.active = make(map[any]bool)
		}
		if o.active[identity] {
			return nil, errors.New("command ownership graph contains a cycle")
		}
		o.active[identity] = true
		defer delete(o.active, identity)
	}
	switch value := value.(type) {
	case nil, bool, int, int64, float64, string, command.Path, command.Cmd, command.CmdArgs, command.Marker:
		return value, nil
	case *string:
		if value == nil {
			return (*string)(nil), nil
		}
		return new(*value), nil
	case *int:
		if value == nil {
			return (*int)(nil), nil
		}
		return new(*value), nil
	case *flow.HTTPFlow:
		if value == nil {
			return nil, nil
		}
		return o.copyFlow(value)
	case *flow.TCPFlow:
		if value == nil {
			return nil, nil
		}
		return o.copyFlow(value)
	case *flow.UDPFlow:
		if value == nil {
			return nil, nil
		}
		return o.copyFlow(value)
	case *flow.DNSFlow:
		if value == nil {
			return nil, nil
		}
		return o.copyFlow(value)
	case []flow.Flow:
		if err := o.conversion.admit(depth, len(value)); err != nil {
			return nil, err
		}
		out := make([]flow.Flow, len(value))
		for n, f := range value {
			copy, err := o.argument(f, depth+1)
			if err != nil {
				return nil, err
			}
			if copy != nil {
				out[n] = copy.(flow.Flow)
			}
		}
		return out, nil
	case []byte:
		return bytes.Clone(value), nil
	case []string:
		if err := o.conversion.admit(depth, len(value)); err != nil {
			return nil, err
		}
		return slices.Clone(value), nil
	case command.CutSpec:
		if err := o.conversion.admit(depth, len(value)); err != nil {
			return nil, err
		}
		return slices.Clone(value), nil
	case command.Data:
		if err := o.conversion.admit(depth, len(value)); err != nil {
			return nil, err
		}
		out := make(command.Data, len(value))
		for n, row := range value {
			copy, err := o.argument(row, depth+1)
			if err != nil {
				return nil, err
			}
			out[n] = copy.([]any)
		}
		return out, nil
	case []any:
		if err := o.conversion.admit(depth, len(value)); err != nil {
			return nil, err
		}
		out := make([]any, len(value))
		for n, x := range value {
			var err error
			out[n], err = o.argument(x, depth+1)
			if err != nil {
				return nil, err
			}
		}
		return out, nil
	case *state.Map:
		if value == nil {
			return nil, nil
		}
		if err := o.conversion.admit(depth, value.Len()); err != nil {
			return nil, err
		}
		out := state.NewMap(value.Len())
		for key, x := range value.All() {
			copy, err := o.argument(x, depth+1)
			if err != nil {
				return nil, err
			}
			if value.IsBytesKey(key) {
				out.SetBytesKey(key, copy)
			} else {
				out.Set(key, copy)
			}
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported native command value: %T", value)
	}
}

func (o *commandOwnership) copyFlow(f flow.Flow) (flow.Flow, error) {
	if o.flows == nil {
		o.flows = make(map[flow.Flow]flow.Flow)
	}
	if prior := o.flows[f]; prior != nil {
		return prior, nil
	}
	copy, err := invocationClone(f)
	if err != nil {
		return nil, err
	}
	o.flows[f] = copy
	return copy, nil
}

func (o *commandOwnership) copyBack() error {
	var errs []error
	for worker, retained := range o.flows {
		// SetState here targets detached worker storage, never a live flow.
		// Its post-call state is copied before the retained graph can run again.
		var request *httpmsg.Request
		var response *httpmsg.Response
		if h, ok := worker.(*flow.HTTPFlow); ok {
			request, response = h.Request, h.Response
		}
		snapshot, err := invocationClone(retained)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := setInvocationState(worker, snapshot); err != nil {
			errs = append(errs, err)
			continue
		}
		worker.Common().Live = snapshot.Common().Live
		if h, ok := worker.(*flow.HTTPFlow); ok {
			source := snapshot.(*flow.HTTPFlow)
			h.Request, h.Response = source.Request, source.Response
			if request != nil && source.Request != nil {
				*request = *source.Request
				h.Request = request
			}
			if response != nil && source.Response != nil {
				*response = *source.Response
				h.Response = response
			}
		}
	}
	return errors.Join(errs...)
}
