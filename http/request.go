// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package http

import (
	"strings"

	"github.com/zchee/mitmproxy-go/internal/state"
)

// Request is an HTTP request.
//
// The fields hold the raw request data. Assigning them directly changes
// nothing else; the Set methods keep dependent data in step the way
// upstream's property setters do (for example, [Request.SetHost] also
// rewrites the Host header and the authority).
type Request struct {
	Message
	// Host is the target server. It comes from the request target or the
	// proxy mode, for example an IP address in transparent mode.
	Host string
	// Port is the target port.
	Port int
	// Method is the request method as received; compare it
	// case-insensitively.
	Method string
	// Scheme is the request scheme, usually "http" or "https".
	Scheme string
	// Authority is the authority of an absolute-form or authority-form
	// request target, or the HTTP/2 and HTTP/3 :authority pseudo header.
	// It is empty for origin-form and asterisk-form requests.
	Authority string
	// Path is the request path including the query, for example
	// "/index.html?a=b", or "*" for OPTIONS requests.
	Path string
}

// MakeRequest builds an HTTP/1.1 request for url with the given body and
// headers, setting Content-Length, as upstream's Request.make does.
func MakeRequest(method, url string, content []byte, headers Headers) (*Request, error) {
	now := state.Now()
	r := &Request{
		HTTPVersion:    "HTTP/1.1",
		Headers:        headers,
		RawContent:     []byte{},
		TimestampStart: now,
		TimestampEnd:   &now,
		Method:         method,
	}
	if r.Headers == nil {
		r.Headers = Headers{}
	}
	if err := r.SetURL(url); err != nil {
		return nil, err
	}
	if content == nil {
		content = []byte{}
	}
	r.SetContent(content)
	return r, nil
}

// String formats r like upstream, for example "Request(GET example.com:80/path)".
func (r *Request) String() string {
	hostport := ""
	if r.Host != "" && r.Port != 0 {
		hostport = r.Host + ":" + itoa(r.Port)
	}
	return "Request(" + strings.ToUpper(r.Method) + " " + hostport + r.Path + ")"
}

// FirstLineFormat returns the request-target form defined by RFC 7230:
// "authority" for CONNECT, "absolute" when an authority is present and
// "relative" otherwise (origin-form and asterisk-form).
func (r *Request) FirstLineFormat() string {
	switch {
	case strings.EqualFold(r.Method, "CONNECT"):
		return "authority"
	case r.Authority != "":
		return "absolute"
	}
	return "relative"
}

// SetAuthority sets the authority, IDNA-encoding a non-ASCII host name.
// A value that cannot be IDNA-encoded is stored as it is.
func (r *Request) SetAuthority(authority string) {
	if a, ok := idnaEncode(authority); ok {
		authority = a
	}
	r.Authority = authority
}

// SetHost sets the target host and updates the Host header and the
// authority if they are present.
func (r *Request) SetHost(host string) {
	r.Host = host
	r.updateHostAndAuthority()
}

// SetPort sets the target port and updates the Host header and the
// authority if they are present.
func (r *Request) SetPort(port int) {
	r.Port = port
	r.updateHostAndAuthority()
}

func (r *Request) updateHostAndAuthority() {
	val := HostPort(r.Scheme, r.Host, r.Port)
	if r.Headers.Has("Host") {
		r.Headers.Set("Host", val)
	}
	if r.Authority != "" {
		r.SetAuthority(val)
	}
}

// HostHeader returns the request's Host header or, for HTTP/2 and HTTP/3,
// its authority, falling back to the Host header. It reports false when
// neither is present.
func (r *Request) HostHeader() (string, bool) {
	if (r.IsHTTP2() || r.IsHTTP3()) && r.Authority != "" {
		return r.Authority, true
	}
	return r.Headers.Lookup("Host")
}

// SetHostHeader sets the Host header or, for HTTP/2 and HTTP/3, the
// authority. For HTTP/2 and HTTP/3 an existing Host header is overwritten
// too, but none is created.
func (r *Request) SetHostHeader(v string) {
	h2 := r.IsHTTP2() || r.IsHTTP3()
	if h2 {
		r.SetAuthority(v)
	}
	if !h2 || r.Headers.Has("Host") {
		r.Headers.Set("Host", v)
	}
}

// RemoveHostHeader removes the Host header and, for HTTP/2 and HTTP/3,
// clears the authority.
func (r *Request) RemoveHostHeader() {
	if r.IsHTTP2() || r.IsHTTP3() {
		r.Authority = ""
	}
	r.Headers.Del("Host")
}

// URL returns the full URL built from scheme, host, port and path, or
// "host:port" for CONNECT requests.
func (r *Request) URL() string {
	if r.FirstLineFormat() == "authority" {
		return r.Host + ":" + itoa(r.Port)
	}
	path := r.Path
	if path == "*" {
		path = ""
	}
	return UnparseURL(r.Scheme, r.Host, r.Port, path)
}

// SetURL sets scheme, host, port and path from an absolute URL.
func (r *Request) SetURL(url string) error {
	scheme, host, port, path, err := ParseURL(url)
	if err != nil {
		return err
	}
	r.Scheme = scheme
	r.SetHost(host)
	r.SetPort(port)
	r.Path = path
	return nil
}

// PrettyHost is like Host but prefers the host from [Request.HostHeader].
// This helps in transparent mode, where Host is only an IP address. The
// Host header may be spoofed, so do not rely on it in adversarial settings.
func (r *Request) PrettyHost() string {
	authority, ok := r.HostHeader()
	if ok && authority != "" {
		host, _, _ := ParseAuthority(authority, false)
		return host
	}
	return r.Host
}

// PrettyURL is like [Request.URL] but uses [Request.PrettyHost] and the
// port of the Host header.
func (r *Request) PrettyURL() string {
	if r.FirstLineFormat() == "authority" {
		return r.Authority
	}
	hostHeader, ok := r.HostHeader()
	if !ok || hostHeader == "" {
		return r.URL()
	}
	host, port, _ := ParseAuthority(hostHeader, false)
	if port <= 0 {
		var ok bool
		if port, ok = DefaultPort(r.Scheme); !ok {
			port = 443
		}
	}
	path := r.Path
	if path == "*" {
		path = ""
	}
	return UnparseURL(r.Scheme, host, port, path)
}

// Anticache removes the headers that could make a server answer with a
// cached response.
func (r *Request) Anticache() {
	r.Headers.Del("if-modified-since")
	r.Headers.Del("if-none-match")
}

// Anticomp asks for an uncompressed response.
func (r *Request) Anticomp() {
	r.Headers.Set("accept-encoding", "identity")
}

// constrainedEncodings are the content codings upstream can decode.
var constrainedEncodings = []string{"gzip", "identity", "deflate", "br", "zstd"}

// ConstrainEncoding limits Accept-Encoding to the codings the proxy can
// decode. Upstream iterates a Python set here, so its output order is not
// defined; this keeps a fixed order.
func (r *Request) ConstrainEncoding() {
	ae := r.Headers.Get("accept-encoding")
	if ae == "" {
		return
	}
	var keep []string
	for _, e := range constrainedEncodings {
		if strings.Contains(ae, e) {
			keep = append(keep, e)
		}
	}
	r.Headers.Set("accept-encoding", strings.Join(keep, ", "))
}

// GetState returns r's serialised state.
func (r *Request) GetState() *state.Map {
	m := state.NewMap(12)
	r.putState(m)
	m.Set("host", r.Host)
	m.Set("port", int64(r.Port))
	m.Set("method", []byte(r.Method))
	m.Set("scheme", []byte(r.Scheme))
	m.Set("authority", []byte(r.Authority))
	m.Set("path", []byte(r.Path))
	return m
}

// SetState replaces r's fields with those in m, consuming m. On error r is
// left unchanged.
func (r *Request) SetState(m *state.Map) error {
	d := state.NewDecoder(m, "Request")
	var n Request
	n.readState(d)
	n.Host = d.String("host")
	n.Port = int(d.Int("port"))
	n.Method = string(d.Bytes("method"))
	n.Scheme = string(d.Bytes("scheme"))
	n.Authority = string(d.Bytes("authority"))
	n.Path = string(d.Bytes("path"))
	if err := d.Finish(); err != nil {
		return err
	}
	*r = n
	return nil
}

// RequestFromState returns a new Request built from m, consuming m.
func RequestFromState(m *state.Map) (*Request, error) {
	r := &Request{}
	if err := r.SetState(m); err != nil {
		return nil, err
	}
	return r, nil
}

// Clone returns a deep copy of r.
func (r *Request) Clone() *Request {
	out := *r
	out.Message = r.clone()
	return &out
}
