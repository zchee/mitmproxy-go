// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package script

import (
	"bufio"
	"bytes"
	"context"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"go.starlark.net/starlark"

	"github.com/zchee/mitmproxy-go/httpmsg"
)

func FuzzScriptSource(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("def request(f):\n    f.comment = \"ok\"\n"))
	f.Add([]byte("def request(:"))
	f.Add([]byte("load(\"../helper.star\", \"helper\")\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > sourceLimit {
			return
		}
		fixture := newFixture(t)
		ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
		defer cancel()
		if err := fixture.master.Options.Update(ctx, map[string]any{"script_max_steps": 2000}); err != nil {
			t.Fatal(err)
		}
		path := fixture.file("fuzz.star", string(data))
		_ = fixture.master.Do(ctx, func(ctx context.Context) error {
			return fixture.master.Options.Update(ctx, map[string]any{"scripts": []string{path}})
		})
	})
}

func FuzzScriptBindings(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("headers\x00X-A\x00one\x00x-a\x00two\xff"))
	f.Add([]byte("integer:18446744073709551616"))
	f.Add([]byte("cycle:list:self"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > conversionLimit {
			return
		}
		fixture := newFixture(t)
		if bytes.Equal(data, []byte("cycle:list:self")) {
			list := starlark.NewList(nil)
			if err := list.Append(list); err != nil {
				t.Fatal(err)
			}
			if _, err := new(conversion).native(list, 0); err == nil {
				t.Fatal("cyclic list was converted")
			}
			return
		}
		if decimal, ok := strings.CutPrefix(string(data), "integer:"); ok {
			n, ok := new(big.Int).SetString(decimal, 10)
			if !ok {
				return
			}
			_, err := intValue(starlark.MakeBigInt(n))
			if !n.IsInt64() && err == nil {
				t.Fatal("overflowing integer assignment accepted")
			}
			return
		}
		if bytes.HasPrefix(data, []byte("headers\x00")) {
			parts := bytes.Split(data, []byte{0})
			if len(parts) < 5 {
				return
			}
			h := httpmsg.Headers{{Name: bytes.Clone(parts[1]), Value: bytes.Clone(parts[2])}, {Name: bytes.Clone(parts[3]), Value: bytes.Clone(parts[4])}}
			if err := fixture.master.Do(t.Context(), func(ctx context.Context) error {
				e := &scriptEntry{owner: fixture.loader, path: "bindings"}
				g := &capabilities{entry: e}
				return g.evaluate(ctx, "conversion", func(_ *starlark.Thread, i *invocation) error {
					wrapped := wrapHeaders(i, &h)
					_, err := headersNative(wrapped)
					return err
				})
			}); err != nil {
				t.Fatal(err)
			}
			return
		}
		values := make([]starlark.Value, len(data))
		for n, b := range data {
			values[n] = starlark.Tuple{starlark.MakeInt(int(b)), starlark.Bytes(string([]byte{b}))}
		}
		_, _ = new(conversion).native(starlark.NewList(values), 0)
	})
}

func FuzzScriptHTTPGetResponse(f *testing.F) {
	f.Add([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
	f.Add([]byte("HTTP/1.1 200 OK\r\nX-A: one\r\nX-A: two\r\nContent-Length: 3\r\n\r\n\x00\xffx"))
	f.Add([]byte("HTTP/1.1 200 OK\r\nX-Large: " + strings.Repeat("x", httpHeaderLimit+1) + "\r\nContent-Length: 0\r\n\r\n"))
	f.Add([]byte("HTTP/1.1 200 OK\r\nContent-Length: 1048577\r\n\r\n" + strings.Repeat("x", httpBodyLimit+1)))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 2*(httpHeaderLimit+httpBodyLimit) {
			return
		}
		response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(data)), nil)
		if err != nil {
			return
		}
		value, err := ownedHTTPResponse(response)
		closeErr := response.Body.Close()
		if err != nil || closeErr != nil {
			return
		}
		content, err := value.(starlark.HasAttrs).Attr("content")
		if err != nil {
			t.Fatal(err)
		}
		if len(content.(starlark.Bytes)) > httpBodyLimit {
			t.Fatal("oversized response escaped conversion")
		}
	})
}
