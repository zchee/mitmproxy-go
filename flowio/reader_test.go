// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package flowio

import (
	"bytes"
	"errors"
	"io"
	"math"
	"math/big"
	"strings"
	"testing"
	"testing/iotest"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flow/state"
	"github.com/zchee/mitmproxy-go/flowio/tnetstring"
	"github.com/zchee/mitmproxy-go/internal/testutil"
	"github.com/zchee/mitmproxy-go/internal/version"
)

const v21Fixture = "mitmproxy/flows/corrupted_gzip_body.mitm"

// rawFlows decodes every flow of a fixture into state dictionaries, without
// migrating them.
func rawFlows(t *testing.T, rel string) []*state.Map {
	t.Helper()
	var out []*state.Map
	for rest := testutil.Fixture(t, rel); len(rest) > 0; {
		v, r, err := tnetstring.Pop(rest)
		if err != nil {
			t.Fatalf("%s: flow %d: %v", rel, len(out), err)
		}
		rest = r
		out = append(out, v.(*state.Map))
	}
	return out
}

// encode writes state dictionaries as a flow file.
func encode(t *testing.T, ms ...*state.Map) []byte {
	t.Helper()
	var buf bytes.Buffer
	for _, m := range ms {
		if err := tnetstring.Dump(&buf, m); err != nil {
			t.Fatal(err)
		}
	}
	return buf.Bytes()
}

// readAll reads every flow from b.
func readAll(t *testing.T, b []byte) ([]flow.Flow, error) {
	t.Helper()
	var flows []flow.Flow
	for f, err := range NewReader(bytes.NewReader(b)).All() {
		if err != nil {
			return flows, err
		}
		flows = append(flows, f)
	}
	return flows, nil
}

// withVersion returns a copy of the v21 fixture's first flow with its
// version replaced.
func withVersion(t *testing.T, v any) []byte {
	t.Helper()
	m := state.CopyMap(rawFlows(t, v21Fixture)[0])
	m.Set("version", v)
	return encode(t, m)
}

func TestReadCurrentFormat(t *testing.T) {
	raw := rawFlows(t, v21Fixture)
	flows, err := readAll(t, testutil.Fixture(t, v21Fixture))
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != len(raw) {
		t.Fatalf("read %d flows, want %d", len(flows), len(raw))
	}
	for i, f := range flows {
		if got := f.GetState(); !state.Equal(raw[i], got) {
			t.Errorf("flow %d: state differs from the file:\nwant %v\n got %v", i, raw[i], got)
		}
	}
	h, ok := flows[0].(*flow.HTTPFlow)
	if !ok {
		t.Fatalf("flow 0 is %T, want *flow.HTTPFlow", flows[0])
	}
	if h.Request.Host != "127.0.0.1" || h.Response.StatusCode != 200 {
		t.Errorf("request host %q, status %d", h.Request.Host, h.Response.StatusCode)
	}
}

func TestReaderNext(t *testing.T) {
	b := testutil.Fixture(t, v21Fixture)
	r := NewReader(iotest.OneByteReader(bytes.NewReader(append(bytes.Repeat(b, 3), b[:10]...))))
	for i := range 3 {
		if _, err := r.Next(); err != nil {
			t.Fatalf("flow %d: %v", i, err)
		}
	}
	_, err := r.Next()
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated fourth flow: error = %v, want io.ErrUnexpectedEOF", err)
	}
	if _, again := r.Next(); again != err {
		t.Errorf("Next after an error returned %v, want the same error %v", again, err)
	}
}

func TestReaderEmpty(t *testing.T) {
	r := NewReader(bytes.NewReader(nil))
	if _, err := r.Next(); err != io.EOF {
		t.Errorf("Next on an empty file: error = %v, want io.EOF", err)
	}
	if _, err := r.Next(); err != io.EOF {
		t.Errorf("second Next on an empty file: error = %v, want io.EOF", err)
	}
	flows, err := readAll(t, nil)
	if err != nil || len(flows) != 0 {
		t.Errorf("All on an empty file = %d flows, %v", len(flows), err)
	}
}

func TestReaderAllStopsEarly(t *testing.T) {
	b := testutil.Fixture(t, v21Fixture)
	r := NewReader(bytes.NewReader(bytes.Repeat(b, 3)))
	for _, err := range r.All() {
		if err != nil {
			t.Fatal(err)
		}
		break
	}
	n := 0
	for _, err := range r.All() {
		if err != nil {
			t.Fatal(err)
		}
		n++
	}
	if n != 2 {
		t.Errorf("after breaking out of All, %d flows were left, want 2", n)
	}
}

func TestReaderErrors(t *testing.T) {
	bigVersion := state.CopyMap(rawFlows(t, v21Fixture)[0])
	bigVersion.Set("version", new(big.Int).Lsh(big.NewInt(1), 70))
	bigInt, err := tnetstring.Dumps(bigVersion)
	if err != nil {
		t.Fatal(err)
	}

	nanPort := state.CopyMap(rawFlows(t, v21Fixture)[0])
	cc, _ := nanPort.Get("client_conn")
	cc.(*state.Map).Set("peername", []any{"127.0.0.1", math.NaN()})

	tests := map[string]struct {
		data    []byte
		wantErr string
		is      error
	}{
		"error: NaN port": {
			data:    encode(t, nanPort),
			wantErr: "cannot convert float NaN to integer",
		},
		"error: HAR document without entries": {
			data:    []byte(`{"log": {}}`),
			wantErr: "Unable to read HAR file. Please provide a valid HAR file",
		},
		"error: HAR document without entries after a byte order mark": {
			data:    []byte(utf8BOM + `{"log": {}}`),
			wantErr: "Unable to read HAR file. Please provide a valid HAR file",
		},
		"error: byte order mark before a tnetstring": {
			data:    append([]byte(utf8BOM), testutil.Fixture(t, v21Fixture)...),
			wantErr: "not a tnetstring: missing or invalid length prefix",
		},
		"error: not a tnetstring": {
			data:    []byte("hello"),
			wantErr: "not a tnetstring: missing or invalid length prefix",
		},
		"error: truncated flow": {
			data:    testutil.Fixture(t, v21Fixture)[:100],
			wantErr: "not a tnetstring: truncated value",
			is:      io.ErrUnexpectedEOF,
		},
		"error: top-level list": {
			data:    []byte("0:]"),
			wantErr: "invalid flow: the top-level value is a list, not a dict",
		},
		"error: unknown flow type": {
			data:    encode(t, dictOf("type", "unknown", "version", int64(flow.FormatVersion))),
			wantErr: "unknown flow type: unknown",
		},
		"error: version beyond int64": {
			data:    bigInt,
			wantErr: "cannot read files with flow format version 1180591620717411303424, please update mitmproxy.",
		},
		"error: integer beyond int64 in a typed field": {
			data:    withBigInt(t, "timestamp_created"),
			wantErr: `field "timestamp_created": integer 18446744073709551616 does not fit in 64 bits`,
		},
		"error: missing version": {
			data:    encode(t, dictOf("type", "http")),
			wantErr: "invalid flow: the version is missing or None",
		},
		"error: float version": {
			data:    withVersion(t, 21.0),
			wantErr: "invalid flow: the version is a float, not an integer or a tuple",
		},
		"error: model rejects the state": {
			data:    encode(t, dictOf("type", "http", "version", int64(flow.FormatVersion))),
			wantErr: "set_state",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			flows, err := readAll(t, tt.data)
			if err == nil {
				t.Fatalf("read %d flows without error", len(flows))
			}
			if tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tt.wantErr)
			}
			if tt.is != nil && !errors.Is(err, tt.is) {
				t.Errorf("errors.Is(%v, %v) = false", err, tt.is)
			}
		})
	}
}

// two64 returns 2**64, an integer that does not fit in an int64.
func two64() *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), 64)
}

// withBigInt returns the v21 fixture's first flow with 2**64 stored under
// key at the top level of the flow.
func withBigInt(t *testing.T, key string) []byte {
	t.Helper()
	m := state.CopyMap(rawFlows(t, v21Fixture)[0])
	m.Set(key, two64())
	return encode(t, m)
}

// metadataFile returns the v21 fixture, written by Writer after set has
// changed the first flow's metadata. set should leave every dictionary with
// one key: a dictionary is written in reverse insertion order and read in
// file order, so the keys of free-form state swap places on every round
// trip, as they do in mitmproxy.
func metadataFile(t *testing.T, set func(md *state.Map)) []byte {
	t.Helper()
	flows, err := readAll(t, testutil.Fixture(t, v21Fixture))
	if err != nil {
		t.Fatal(err)
	}
	set(flows[0].Common().Metadata)
	return writeAll(t, flows)
}

// bigMetadataFile returns the v21 fixture with the list [2**64, -2**64]
// stored in the first flow's metadata.
func bigMetadataFile(t *testing.T) []byte {
	t.Helper()
	return metadataFile(t, func(md *state.Map) {
		md.Set("big", []any{two64(), new(big.Int).Neg(two64())})
	})
}

// bytesKeyMetadataFile returns the v21 fixture with {b"\xff": {b"k": 1}}
// as the first flow's metadata: byte-string keys, one of them not UTF-8.
func bytesKeyMetadataFile(t *testing.T) []byte {
	t.Helper()
	return metadataFile(t, func(md *state.Map) {
		inner := state.NewMap(1)
		inner.SetBytesKey("k", int64(1))
		md.SetBytesKey("\xff", inner)
	})
}

// TestBytesKeysInMetadata checks that dictionary keys keep their kind
// through a read and a write: a byte-string key is written back with the ,
// tag, even when it is not UTF-8, as mitmproxy writes a bytes key.
func TestBytesKeysInMetadata(t *testing.T) {
	src := bytesKeyMetadataFile(t)
	if !bytes.Contains(src, []byte("8:metadata;15:1:\xff,8:1:k,1:1#}}")) {
		t.Fatalf("the written file does not hold metadata {b'\\xff': {b'k': 1}}:\n%q", src)
	}

	flows, err := readAll(t, src)
	if err != nil {
		t.Fatalf("reading a flow with byte-string metadata keys: %v", err)
	}
	md := flows[0].Common().Metadata
	inner, _ := md.Get("\xff")
	if !md.IsBytesKey("\xff") || !inner.(*state.Map).IsBytesKey("k") {
		t.Errorf("metadata = %v, want {b\"\\xff\": {b\"k\": 1}}", md)
	}
	if out := writeAll(t, flows); !bytes.Equal(out, src) {
		t.Errorf("Write(Read(file)) differs from the file:\nwant %q\n got %q", src, out)
	}
}

// TestBigIntInMetadata checks that an integer beyond int64 in free-form
// state, which a Python addon can store, survives a read and a write.
func TestBigIntInMetadata(t *testing.T) {
	src := bigMetadataFile(t)
	if !bytes.Contains(src, []byte("20:18446744073709551616#")) || !bytes.Contains(src, []byte("21:-18446744073709551616#")) {
		t.Fatalf("the written file does not hold 2**64 and -2**64 as integers:\n%q", src)
	}

	flows, err := readAll(t, src)
	if err != nil {
		t.Fatalf("reading a flow with 2**64 in its metadata: %v", err)
	}
	want := []any{two64(), new(big.Int).Neg(two64())}
	if got, _ := flows[0].Common().Metadata.Get("big"); !state.Equal(got, want) {
		t.Errorf("metadata[big] = %v, want %v", got, want)
	}
	if out := writeAll(t, flows); !bytes.Equal(out, src) {
		t.Errorf("Write(Read(file)) differs from the file:\nwant %q\n got %q", src, out)
	}
}

func dictOf(kv ...any) *state.Map {
	m := state.NewMap(len(kv) / 2)
	for i := 0; i < len(kv); i += 2 {
		m.Set(kv[i].(string), kv[i+1])
	}
	return m
}

// TestVersionErrors checks mitmproxy's message for versions it cannot read,
// rendered as Python renders them.
func TestVersionErrors(t *testing.T) {
	prefix := version.String() + " cannot read files with flow format version "
	tests := map[string]struct {
		data []byte
		want string
	}{
		"error: hand-made version 22":   {data: withVersion(t, int64(22)), want: prefix + "22, please update mitmproxy."},
		"error: hand-made version 1000": {data: withVersion(t, int64(1000)), want: prefix + "1000, please update mitmproxy."},
		"error: version 0":              {data: []byte("14:7:version;1:0#}"), want: prefix + "0."},
		"error: negative version":       {data: withVersion(t, int64(-1)), want: prefix + "-1."},
		"error: version 17":             {data: withVersion(t, int64(17)), want: prefix + "17."},
		"error: three-part tuple":       {data: withVersion(t, []any{int64(0), int64(10), int64(1)}), want: prefix + "(0, 10)."},
		"error: one-part tuple":         {data: withVersion(t, []any{int64(5)}), want: prefix + "(5,)."},
		"error: empty tuple":            {data: withVersion(t, []any{}), want: prefix + "()."},
		"error: string version":         {data: withVersion(t, "21"), want: prefix + "('2', '1')."},
		"error: bytes version":          {data: withVersion(t, []byte("21")), want: prefix + "(50, 49)."},
		"error: dict version":           {data: withVersion(t, dictOf("a", nil)), want: prefix + "('a',)."},
		"error: bool version":           {data: withVersion(t, true), want: prefix + "True."},
		"error: false version":          {data: withVersion(t, false), want: prefix + "False."},
		"error: mixed tuple": {
			data: withVersion(t, []any{"it's", []byte("a\"\x00\\")}),
			want: prefix + `("it's", b'a"\x00\\').`,
		},
		"error: nested tuple": {
			data: withVersion(t, []any{[]any{nil, 1.5, true, false}, dictOf("k", "\t\n\r\x01é\u200b")}),
			want: prefix + `([None, 1.5, True, False], {'k': '\t\n\r\x01é\u200b'}).`,
		},
		"error: quotes in bytes": {
			data: withVersion(t, []any{[]byte("'"), []byte("'\"\t\n\r\xff")}),
			want: prefix + `(b"'", b'\'"\t\n\r\xff').`,
		},
		"error: quotes in text": {
			data: withVersion(t, []any{"'\"\\", "\x7f\U0001F600\U000E0001"}),
			want: prefix + `('\'"\\', '\x7f` + "\U0001F600" + `\U000e0001').`,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := readAll(t, tt.data)
			if _, ok := errors.AsType[*VersionError](err); !ok {
				t.Fatalf("error = %v (%T), want a *VersionError", err, err)
			}
			if diff := gocmp.Diff(tt.want, err.Error()); diff != "" {
				t.Errorf("message mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestOldDumpfiles checks the exact message for every fixture older than
// format 18. mitmproxy itself migrates these; mitmproxy-go reads format 18
// and later only.
func TestOldDumpfiles(t *testing.T) {
	prefix := version.String() + " cannot read files with flow format version "
	tests := map[string]struct {
		rel  string
		want string
	}{
		"error: dumpfile-010":         {rel: "mitmproxy/dumpfile-010.mitm", want: prefix + "(0, 10)."},
		"error: dumpfile-011":         {rel: "mitmproxy/dumpfile-011.mitm", want: prefix + "(0, 11)."},
		"error: dumpfile-018":         {rel: "mitmproxy/dumpfile-018.mitm", want: prefix + "(0, 18)."},
		"error: dumpfile-019":         {rel: "mitmproxy/dumpfile-019.mitm", want: prefix + "7."},
		"error: dumpfile-10":          {rel: "mitmproxy/dumpfile-10.mitm", want: prefix + "10."},
		"error: dumpfile-7":           {rel: "mitmproxy/dumpfile-7.mitm", want: prefix + "11."},
		"error: dumpfile-7-websocket": {rel: "mitmproxy/dumpfile-7-websocket.mitm", want: prefix + "7."},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			flows, err := readAll(t, testutil.Fixture(t, tt.rel))
			if len(flows) != 0 {
				t.Errorf("read %d flows before the error", len(flows))
			}
			if err == nil {
				t.Fatal("read without error")
			}
			if diff := gocmp.Diff(tt.want, err.Error()); diff != "" {
				t.Errorf("message mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
