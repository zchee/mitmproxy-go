// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httplayer

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zchee/mitmproxy-go/httpmsg"
	"github.com/zchee/mitmproxy-go/internal/http1"
	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

// http1ReadBuffer is the bufio buffer feeding the head parser. Lines longer
// than the buffer are handled by the parser's own accumulation; bodies read
// in larger chunks bypass the buffer entirely.
const http1ReadBuffer = 8 << 10

// http1BodyChunk bounds one body read, and so the size of one data event.
const http1BodyChunk = 64 << 10

// pushbackReader lets consumed-but-unprocessed bytes be returned to the
// stream, for the next head parse after a wait or the replay at a pipe
// handover. push requires that no read is in flight and that every reader
// above it, including the endpoint's bufio.Reader, is empty.
type pushbackReader struct {
	prefix []byte
	r      io.Reader
}

func (p *pushbackReader) Read(b []byte) (int, error) {
	if len(p.prefix) != 0 {
		n := copy(b, p.prefix)
		p.prefix = p.prefix[n:]
		return n, nil
	}
	return p.r.Read(b)
}

func (p *pushbackReader) push(b []byte) {
	if len(b) != 0 {
		p.prefix = append(b, p.prefix...)
	}
}

// http1State is the receive-side state of an HTTP/1 endpoint.
type http1State uint8

const (
	// http1Headers parses the next message head.
	http1Headers http1State = iota
	// http1Body streams the current message body.
	http1Body
	// http1Wait holds between the end of one direction and the end of the
	// exchange, buffering early bytes without interpreting them.
	http1Wait
	// http1Pipe relays raw bytes after a 101 upgrade or a CONNECT success.
	http1Pipe
	// http1Done refuses further messages; the connection is finished.
	http1Done
)

// http1Conn holds what the client-facing and server-facing HTTP/1 endpoints
// share: the transport, the parser input, the per-exchange bookkeeping and
// the write path. One goroutine owns Receive; the send gate serializes entire
// Send operations and allows callers waiting for another Send to cancel.
// Cross-direction state is guarded by mu, never held during socket reads or
// writes. A deadline poke under mu wakes a reader parked between exchanges.
type http1Conn struct {
	conn     layer.Conn
	src      *pushbackReader
	br       *bufio.Reader
	wire     *wireStore
	fidelity *http1.FidelityCounter

	send chan struct{}

	mu           sync.Mutex
	state        http1State
	request      *httpmsg.Request
	response     *httpmsg.Response
	requestDone  bool
	responseDone bool
	writeClosed  bool
	waiting      bool
	waitBuf      []byte
}

func newHTTP1Conn(conn layer.Conn, wire *wireStore, fidelity *http1.FidelityCounter) http1Conn {
	src := &pushbackReader{r: conn}
	return http1Conn{
		conn: conn, src: src, br: bufio.NewReaderSize(src, http1ReadBuffer),
		wire: wire, fidelity: fidelity,
		send: make(chan struct{}, 1),
	}
}

// acquireSend claims the send side for one whole Send call, so concurrent
// Sends from other streams interleave at event rather than byte granularity.
// A caller parked behind another Send honors its own context.
func (c *http1Conn) acquireSend(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case c.send <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *http1Conn) releaseSend() { <-c.send }

// readCtx runs one blocking read honoring ctx: cancellation pokes the read
// deadline so the call unblocks without waiting for the peer. The cancel
// callback is joined before the deadline resets, so a late poke cannot
// outlive this call and time out an unrelated later read.
func (c *http1Conn) readCtx(ctx context.Context, read func() (int, error)) (int, error) {
	fired := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = c.conn.SetReadDeadline(time.Now())
		close(fired)
	})
	n, err := read()
	if !stop() {
		<-fired
		_ = c.conn.SetReadDeadline(time.Time{})
	}
	if err != nil && ctx.Err() != nil && isTimeout(err) {
		return n, ctx.Err()
	}
	return n, err
}

// writeCtx writes all of b honoring ctx. The caller holds the send gate, so
// transport writes never interleave. The cancel callback is joined before
// the deadline resets, as in readCtx.
func (c *http1Conn) writeCtx(ctx context.Context, b []byte) error {
	if len(b) == 0 {
		return nil
	}
	fired := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = c.conn.SetWriteDeadline(time.Now())
		close(fired)
	})
	_, err := c.conn.Write(b)
	if !stop() {
		<-fired
		_ = c.conn.SetWriteDeadline(time.Time{})
	}
	if err != nil && ctx.Err() != nil && isTimeout(err) {
		return ctx.Err()
	}
	return err
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// closeWrite half-closes the transport once.
func (c *http1Conn) closeWrite() {
	c.mu.Lock()
	closed := c.writeClosed
	c.writeClosed = true
	c.mu.Unlock()
	if !closed {
		_ = c.conn.CloseWrite()
	}
}

// kick unblocks a receive side parked in the wait state so it observes a
// state transition. The caller holds mu.
func (c *http1Conn) kick() {
	if c.waiting {
		_ = c.conn.SetReadDeadline(time.Now())
	}
}

// chunkedTE reports whether headers declare chunked transfer encoding, with
// upstream's substring match on the joined header value.
func chunkedTE(headers httpmsg.Headers) bool {
	return strings.Contains(strings.ToLower(headers.Get("transfer-encoding")), "chunked")
}

// writeData writes one body chunk with the message's declared framing:
// one chunk frame under chunked transfer encoding, the raw bytes otherwise.
// The send path does not enforce Content-Length, as upstream does not.
func (c *http1Conn) writeData(ctx context.Context, chunked bool, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if chunked {
		framed := make([]byte, 0, len(data)+20)
		framed = strconv.AppendInt(framed, int64(len(data)), 16)
		framed = append(framed, '\r', '\n')
		framed = append(framed, data...)
		framed = append(framed, '\r', '\n')
		return c.writeCtx(ctx, framed)
	}
	return c.writeCtx(ctx, data)
}

// writeLastChunk terminates a chunked body, carrying any trailers.
func (c *http1Conn) writeLastChunk(ctx context.Context, trailers httpmsg.Headers) error {
	out := []byte("0\r\n")
	out = append(out, trailers.Bytes()...)
	out = append(out, '\r', '\n')
	return c.writeCtx(ctx, out)
}

// shouldMakePipe reports whether the exchange switches to a raw byte stream,
// as after a 101 upgrade or a successful CONNECT.
func shouldMakePipe(request *httpmsg.Request, response *httpmsg.Response) bool {
	if response.StatusCode == 101 {
		return true
	}
	return response.StatusCode == 200 && strings.ToUpper(request.Method) == "CONNECT"
}

// connectionDone reports whether the connection cannot carry another
// exchange: the response needs read-until-close framing, either peer asked
// for closure, or singleUse forces one exchange per connection, as upstream
// does for HTTP/2 and HTTP/3 requests proxied over HTTP/1.
func connectionDone(request *httpmsg.Request, response *httpmsg.Response, singleUse bool) bool {
	size, err := http1.ExpectedBodySize(request, response)
	untilClose := err == nil && size.Mode == http1.BodyUntilClose
	return untilClose ||
		http1.ConnectionClose(request.HTTPVersion, request.Headers) ||
		http1.ConnectionClose(response.HTTPVersion, response.Headers) ||
		singleUse
}

// startPipe moves the receive side to raw relay. The caller holds mu.
func (c *http1Conn) startPipe() {
	c.state = http1Pipe
	c.kick()
}

// takeWaitBufLocked claims the bytes buffered ahead of the raw relay, with
// their superfluous leading newlines removed, as upstream's make_pipe strips
// only what was already buffered at the switch. The caller holds mu.
func (c *http1Conn) takeWaitBufLocked() []byte {
	buffered := bytes.TrimLeft(c.waitBuf, "\r\n")
	c.waitBuf = nil
	return buffered
}

// drainBuffered moves everything already buffered above the transport into
// waitBuf, bounded by layer.MaxRecordBytes. It never blocks. The receive
// goroutine owns br, so this runs only on that goroutine.
func (c *http1Conn) drainBuffered() error {
	for {
		n := c.br.Buffered()
		if n == 0 {
			return nil
		}
		if len(c.waitBuf)+n > layer.MaxRecordBytes {
			return fmt.Errorf("HTTP/1 connection buffered more than %d bytes before the exchange completed", layer.MaxRecordBytes)
		}
		chunk, err := c.br.Peek(n)
		if err != nil {
			return err
		}
		c.waitBuf = append(c.waitBuf, chunk...)
		if _, err := c.br.Discard(n); err != nil {
			return err
		}
	}
}

// errorMessage renders err the way upstream embeds it in protocol errors and
// error pages: without Go's unexpected-EOF wrapping suffix, and without the
// parser's sentinel prefix, which upstream's bare ValueError does not carry.
func errorMessage(err error) string {
	msg := strings.TrimSuffix(err.Error(), ": "+io.ErrUnexpectedEOF.Error())
	if cut, ok := strings.CutPrefix(msg, http1.ErrInvalidHead.Error()+": "); ok {
		return cut
	}
	return msg
}
