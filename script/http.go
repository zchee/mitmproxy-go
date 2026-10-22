// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package script

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"

	"github.com/zchee/mitmproxy-go/addon"
)

const (
	httpBodyLimit   = 1 << 20
	httpHeaderLimit = 64 << 10
)

func (l *Loader) initHTTP() {
	l.transport = &http.Transport{
		Proxy: nil, DialContext: l.dialHTTP,
		DisableCompression: true, MaxResponseHeaderBytes: httpHeaderLimit,
		TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 10 * time.Second,
		IdleConnTimeout: 30 * time.Second, MaxIdleConns: 64, MaxIdleConnsPerHost: 4,
	}
	l.client = &http.Client{Transport: l.transport, Timeout: 10 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 3 {
			return errors.New("ctx.http_get exceeds 3 redirects")
		}
		return validateHTTPURL(req.URL)
	}}
}

func validateHTTPURL(u *url.URL) error {
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("ctx.http_get requires HTTP or HTTPS")
	}
	if u.User != nil {
		return errors.New("ctx.http_get rejects URL userinfo")
	}
	if u.Hostname() == "" {
		return errors.New("ctx.http_get requires a host")
	}
	return nil
}

func (l *Loader) dialHTTP(ctx context.Context, network, address string) (net.Conn, error) {
	if l.cfg.ListenAddrs == nil {
		return nil, errors.New("ctx.http_get requires the master's listener-address capability")
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	var last error
	for _, ip := range ips {
		if err := l.rejectListener(ctx, ip, port); err != nil {
			return nil, err
		}
		conn, err := (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(ip.String(), portText))
		if err == nil {
			return conn, nil
		}
		last = err
	}
	if last == nil {
		last = errors.New("ctx.http_get destination has no address")
	}
	return nil, last
}

func (l *Loader) rejectListener(ctx context.Context, ip netip.Addr, port int) error {
	local := ip.IsLoopback() || ip.IsUnspecified()
	if !local {
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			return errors.New("ctx.http_get cannot verify local addresses")
		}
		for _, addr := range addrs {
			prefix, err := netip.ParsePrefix(addr.String())
			if err == nil && prefix.Addr().Unmap() == ip.Unmap() {
				local = true
				break
			}
		}
	}
	for _, listener := range l.cfg.ListenAddrs() {
		if listener.Port != port {
			continue
		}
		host := strings.Trim(listener.Host, "[]")
		bound, err := netip.ParseAddr(host)
		if host == "" || (err == nil && bound.IsUnspecified()) {
			if local {
				return errors.New("ctx.http_get rejects this master's proxy listener")
			}
			continue
		}
		if err == nil {
			if bound.Unmap() == ip.Unmap() {
				return errors.New("ctx.http_get rejects this master's proxy listener")
			}
			continue
		}
		addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return errors.New("ctx.http_get cannot verify proxy listener")
		}
		for _, bound := range addresses {
			if bound.Unmap() == ip.Unmap() {
				return errors.New("ctx.http_get rejects this master's proxy listener")
			}
		}
	}
	return nil
}

func (i *invocation) blocking(fn func(context.Context) error) error {
	if err := i.check(); err != nil {
		return err
	}
	if i.worker {
		return fn(i.ctx)
	}
	g := i.graph
	prior := g.entry.owner.current.Swap(nil)
	i.active = false
	ctx, err := addon.Concurrent(i.ctx, fn)
	i.ctx = ctx
	if errors.Is(err, addon.ErrSyncContext) {
		i.active = true
		g.entry.owner.current.Store(prior)
		return fn(i.ctx)
	}
	// Cancellation of reacquisition leaves no valid frame; do not reinstall
	// a shared scope or allow any subsequent wrapper access.
	if ctx.Err() == nil {
		i.active = true
		g.entry.owner.current.Store(prior)
	}
	return err
}

func (g *capabilities) httpGet(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var text string
	if err := starlark.UnpackArgs("ctx.http_get", args, kwargs, "url", &text); err != nil {
		return nil, err
	}
	i, err := threadInvocation(thread)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(text)
	if err != nil {
		return nil, errors.New("ctx.http_get: invalid URL")
	}
	if err = validateHTTPURL(u); err != nil {
		return nil, err
	}
	l := g.entry.owner
	if l.cfg.ListenAddrs == nil {
		return nil, errors.New("ctx.http_get requires the master's listener-address capability")
	}
	select {
	case g.entry.httpSlots <- struct{}{}:
		defer func() { <-g.entry.httpSlots }()
	default:
		return nil, errors.New("ctx.http_get busy: 32 operations already admitted")
	}
	var response starlark.Value
	err = i.blocking(func(ctx context.Context) (err error) {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return errors.New("ctx.http_get: invalid request")
		}
		resp, err := l.client.Do(req)
		if err != nil {
			return fmt.Errorf("ctx.http_get failed: %w", sanitizeHTTPError(err))
		}
		defer func() { err = errors.Join(err, resp.Body.Close()) }()
		response, err = ownedHTTPResponse(resp)
		return err
	})
	return response, err
}

func sanitizeHTTPError(err error) error {
	// net/http's url.Error includes the original URL. Keep only the cause,
	// so a failing request never logs an operator-supplied credential/query.
	if e, ok := errors.AsType[*url.Error](err); ok {
		return e.Err
	}
	return err
}

func ownedHTTPResponse(resp *http.Response) (starlark.Value, error) {
	headerBytes := len(resp.Proto) + len(resp.Status) + 4
	for name, values := range resp.Header {
		for _, value := range values {
			if len(name) > httpHeaderLimit-headerBytes || len(value) > httpHeaderLimit-headerBytes-len(name) {
				return nil, errors.New("ctx.http_get response headers exceed 65536 bytes")
			}
			headerBytes += len(name) + len(value) + 4
			if headerBytes > httpHeaderLimit {
				return nil, errors.New("ctx.http_get response headers exceed 65536 bytes")
			}
		}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, httpBodyLimit+1))
	if err != nil {
		return nil, err
	}
	if len(data) > httpBodyLimit {
		return nil, fmt.Errorf("ctx.http_get response exceeds %d bytes", httpBodyLimit)
	}
	headers := starlark.NewDict(len(resp.Header))
	for name, values := range resp.Header {
		if err := headers.SetKey(starlark.String(name), starlark.String(strings.Join(values, ", "))); err != nil {
			return nil, err
		}
	}
	headers.Freeze()
	response := &starlarkstruct.Module{Name: "http_response", Members: starlark.StringDict{"status_code": starlark.MakeInt(resp.StatusCode), "headers": headers, "content": starlark.Bytes(data)}}
	response.Freeze()
	return response, nil
}
