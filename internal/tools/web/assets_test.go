// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package web

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/csv"
	"errors"
	"fmt"
	"html"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestWebAssets(t *testing.T) {
	tests := map[string]struct{ run func(*testing.T) }{
		"upstream": {run: func(t *testing.T) {
			tests := map[string]struct{ run func(*testing.T) }{
				"test_index": {run: func(t *testing.T) {
					server := httptest.NewServer(IndexHandler())
					t.Cleanup(server.Close)
					response, body := fetchAsset(t, server, "GET", "/", nil)
					if response.StatusCode != http.StatusOK {
						t.Fatalf("index status = %d, body = %q", response.StatusCode, body)
					}
					if bytes.Contains(body, []byte(`="/`)) {
						t.Fatal("index contains root-relative URLs")
					}
				}},
				"test_javascript_mime_type": {run: func(t *testing.T) {
					server := httptest.NewServer(StaticHandler())
					t.Cleanup(server.Close)
					entries, err := assets.ReadDir("static")
					if err != nil {
						t.Fatal(err)
					}
					var found bool
					for _, entry := range entries {
						if !strings.HasSuffix(entry.Name(), ".js") {
							continue
						}
						found = true
						response, _ := fetchAsset(t, server, "GET", "/static/"+entry.Name(), nil)
						if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "text/javascript" {
							t.Fatalf("%s: status = %d, MIME = %q", entry.Name(), response.StatusCode, response.Header.Get("Content-Type"))
						}
					}
					if !found {
						t.Fatal("no JavaScript files in embedded static directory")
					}
				}},
			}
			for name, test := range tests {
				t.Run(name, test.run)
			}
		}},
		"manifest": {run: testAssetManifest},
		"methods":  {run: testAssetMethods},
		"cache":    {run: testAssetCache},
		"range":    {run: testAssetRange},
		"paths":    {run: testAssetPaths},
		"login":    {run: testAssetLogin},
	}
	for name, test := range tests {
		t.Run(name, test.run)
	}
}

func fetchAsset(t *testing.T, server *httptest.Server, method, path string, headers http.Header) (*http.Response, []byte) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), method, server.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header = headers.Clone()
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = response.Body.Close() })
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response, body
}

func testAssetManifest(t *testing.T) {
	manifest, err := assets.ReadFile("assets.tsv")
	if err != nil {
		t.Fatal(err)
	}
	reader := csv.NewReader(bytes.NewReader(manifest))
	reader.Comma = '\t'
	reader.Comment = '#'
	reader.FieldsPerRecord = 6
	rows, err := reader.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, row := range rows {
		name, source, mode, blob, size, digest := row[0], row[1], row[2], row[3], row[4], row[5]
		paths = append(paths, name)
		if mode != "100644" || len(blob) != 40 || len(digest) != 64 {
			t.Fatalf("invalid provenance row: %q", row)
		}
		if name == "templates/login.html" {
			if source != "mitmproxy/tools/web/templates/login.html" {
				t.Fatalf("unexpected login reference source: %q", source)
			}
			continue // The runtime login is translated; its reference is imported separately.
		}
		body, err := assets.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if diff := gocmp.Diff([]string{size, digest}, []string{strconv.Itoa(len(body)), fmt.Sprintf("%x", sha256.Sum256(body))}); diff != "" {
			t.Errorf("%s provenance (-want +got):\n%s", name, diff)
		}
	}
	want := []string{
		"UPSTREAM_LICENSE", "index.html", "static/favicon.ico",
		"static/fontawesome-webfont-B-jkhYfk.woff2", "static/fontawesome-webfont-CDK5bt4p.woff",
		"static/fontawesome-webfont-CQDK8MU3.ttf", "static/fontawesome-webfont-D13rzr4g.svg",
		"static/fontawesome-webfont-G5YE5S7X.eot", "static/index-Be7e-cwP.js",
		"static/index-DhPPoJ7G.css", "static/vendor-BS4xPthR.js", "static/vendor-Cg3S-P9H.css",
		"templates/login.html",
	}
	slices.Sort(paths)
	slices.Sort(want)
	if diff := gocmp.Diff(want, paths); diff != "" {
		t.Fatalf("manifest membership (-want +got):\n%s", diff)
	}
	var staticPaths []string
	if err := fs.WalkDir(assets, "static", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			staticPaths = append(staticPaths, name)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var wantStatic []string
	for _, name := range want {
		if strings.HasPrefix(name, "static/") {
			wantStatic = append(wantStatic, name)
		}
	}
	if diff := gocmp.Diff(wantStatic, staticPaths); diff != "" {
		t.Errorf("static membership (-want +got):\n%s", diff)
	}
}

func testAssetMethods(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle("/static/", StaticHandler())
	mux.Handle("/", IndexHandler())
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	entries, err := assets.ReadDir("static")
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct{ path string }{"index": {path: "/"}}
	for _, entry := range entries {
		tests[entry.Name()] = struct{ path string }{path: "/static/" + entry.Name()}
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			file := strings.TrimPrefix(test.path, "/")
			if file == "" {
				file = "index.html"
			}
			want, err := assets.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			get, body := fetchAsset(t, server, "GET", test.path, nil)
			if get.StatusCode != http.StatusOK || !bytes.Equal(want, body) {
				t.Fatalf("GET %s: status = %d, body digest = %x, want %x", test.path, get.StatusCode, sha256.Sum256(body), sha256.Sum256(want))
			}
			head, body := fetchAsset(t, server, "HEAD", test.path, nil)
			if head.StatusCode != http.StatusOK || len(body) != 0 || head.ContentLength != int64(len(want)) {
				t.Fatalf("HEAD %s: status = %d, body bytes = %d, content length = %d", test.path, head.StatusCode, len(body), head.ContentLength)
			}
			for _, key := range []string{"Content-Type", "Content-Length", "Etag", "Last-Modified", "Accept-Ranges"} {
				if diff := gocmp.Diff(get.Header.Values(key), head.Header.Values(key)); diff != "" {
					t.Errorf("GET/HEAD %s (-want +got):\n%s", key, diff)
				}
			}
		})
	}
}

func testAssetCache(t *testing.T) {
	server := httptest.NewServer(StaticHandler())
	t.Cleanup(server.Close)
	const name = "static/index-Be7e-cwP.js"
	body, err := assets.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	etag := fmt.Sprintf(`"%x"`, sha512.Sum512(body))
	modified := time.Unix(1791038697, 0).UTC().Format(http.TimeFormat)
	tests := map[string]struct {
		query   string
		headers http.Header
		status  int
		cached  bool
	}{
		"ordinary":         {status: 200},
		"unrelated_query":  {query: "?other=1", status: 200},
		"versioned":        {query: "?v=abc", status: 200, cached: true},
		"empty_version":    {query: "?v=", status: 200, cached: true},
		"bare_version":     {query: "?v", status: 200, cached: true},
		"etag":             {headers: http.Header{"If-None-Match": {etag}}, status: 304},
		"weak_etag":        {headers: http.Header{"If-None-Match": {"W/" + etag}}, status: 304},
		"any_etag":         {headers: http.Header{"If-None-Match": {"*"}}, status: 304},
		"modified":         {headers: http.Header{"If-Modified-Since": {modified}}, status: 304},
		"old_modified":     {headers: http.Header{"If-Modified-Since": {time.Unix(1791038696, 0).UTC().Format(http.TimeFormat)}}, status: 200},
		"invalid_modified": {headers: http.Header{"If-Modified-Since": {"invalid"}}, status: 200},
		"etag_precedence":  {headers: http.Header{"If-None-Match": {`"other"`}, "If-Modified-Since": {modified}}, status: 200},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			before := time.Now().UTC().Add(315360000 * time.Second).Truncate(time.Second)
			response, body := fetchAsset(t, server, "GET", "/static/index-Be7e-cwP.js"+test.query, test.headers)
			after := time.Now().UTC().Add(315360000 * time.Second)
			if response.StatusCode != test.status {
				t.Fatalf("status = %d, want %d", response.StatusCode, test.status)
			}
			if response.Header.Get("Etag") != etag {
				t.Errorf("ETag = %q, want %q", response.Header.Get("Etag"), etag)
			}
			if test.status == http.StatusNotModified {
				if len(body) != 0 {
					t.Errorf("304 has %d body bytes", len(body))
				}
			} else if response.Header.Get("Last-Modified") != modified || response.Header.Get("Accept-Ranges") != "bytes" {
				t.Errorf("static validators = %v", response.Header)
			}
			if test.cached {
				expires, err := http.ParseTime(response.Header.Get("Expires"))
				if err != nil || expires.Before(before) || expires.After(after) || response.Header.Get("Cache-Control") != "max-age=315360000" {
					t.Errorf("version cache headers = %v, expiry error = %v", response.Header, err)
				}
			} else if response.Header.Get("Cache-Control") != "" || response.Header.Get("Expires") != "" {
				t.Errorf("ordinary static response has explicit cache lifetime: %v", response.Header)
			}
		})
	}
}

func testAssetRange(t *testing.T) {
	server := httptest.NewServer(StaticHandler())
	t.Cleanup(server.Close)
	body, err := assets.ReadFile("static/index-Be7e-cwP.js")
	if err != nil {
		t.Fatal(err)
	}
	etag := fmt.Sprintf(`"%x"`, sha512.Sum512(body))
	tests := map[string]struct {
		rangeValue string
		ifRange    string
		status     int
		body       []byte
		content    string
	}{
		"first_bytes":   {rangeValue: "bytes=0-9", status: 206, body: body[:10], content: fmt.Sprintf("bytes 0-9/%d", len(body))},
		"suffix":        {rangeValue: "bytes=-10", status: 206, body: body[len(body)-10:], content: fmt.Sprintf("bytes %d-%d/%d", len(body)-10, len(body)-1, len(body))},
		"open_end":      {rangeValue: fmt.Sprintf("bytes=%d-", len(body)-10), status: 206, body: body[len(body)-10:], content: fmt.Sprintf("bytes %d-%d/%d", len(body)-10, len(body)-1, len(body))},
		"matching_etag": {rangeValue: "bytes=0-9", ifRange: etag, status: 206, body: body[:10], content: fmt.Sprintf("bytes 0-9/%d", len(body))},
		"matching_date": {rangeValue: "bytes=0-9", ifRange: time.Unix(1791038697, 0).UTC().Format(http.TimeFormat), status: 206, body: body[:10], content: fmt.Sprintf("bytes 0-9/%d", len(body))},
		"stale_etag":    {rangeValue: "bytes=0-9", ifRange: `"old"`, status: 200, body: body},
		"unsatisfiable": {rangeValue: fmt.Sprintf("bytes=%d-", len(body)), status: 416, content: fmt.Sprintf("bytes */%d", len(body))},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			headers := http.Header{"Range": {test.rangeValue}}
			if test.ifRange != "" {
				headers.Set("If-Range", test.ifRange)
			}
			response, got := fetchAsset(t, server, "GET", "/static/index-Be7e-cwP.js", headers)
			if response.StatusCode != test.status || response.Header.Get("Content-Range") != test.content {
				t.Fatalf("range status = %d, headers = %v", response.StatusCode, response.Header)
			}
			if test.status != 416 && !bytes.Equal(test.body, got) {
				t.Errorf("range returned incorrect bytes: got %d bytes, want %d", len(got), len(test.body))
			}
		})
	}
}

func testAssetPaths(t *testing.T) {
	server := httptest.NewServer(StaticHandler())
	t.Cleanup(server.Close)
	tests := map[string]struct {
		path   string
		method string
		status int
	}{
		"missing":           {path: "/static/missing.js", status: 404},
		"directory":         {path: "/static/", status: 403},
		"outside_prefix":    {path: "/UPSTREAM_LICENSE", status: 404},
		"embedded_private":  {path: "/static/UPSTREAM_LICENSE", status: 404},
		"traversal":         {path: "/static/../index.html", status: 403},
		"escaped_traversal": {path: "/static/%2e%2e%2findex.html", status: 403},
		"double_escaped":    {path: "/static/%252e%252e%252findex.html", status: 404},
		"absolute_path":     {path: "/static/%2findex.html", status: 403},
		"escaped_name":      {path: "/static/%69ndex-Be7e-cwP.js", status: 200},
		"escaped_separator": {path: "/static/a%2f..%2findex-Be7e-cwP.js", status: 200},
		"nul":               {path: "/static/index-Be7e-cwP.js%00", status: 404},
		"backslash":         {path: "/static/..%5cindex.html", status: 404},
		"post":              {path: "/static/index-Be7e-cwP.js", method: "POST", status: 405},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			method := test.method
			if method == "" {
				method = "GET"
			}
			response, body := fetchAsset(t, server, method, test.path, nil)
			if response.StatusCode != test.status {
				t.Errorf("%s %s: status = %d, want %d, body = %q", method, test.path, response.StatusCode, test.status, body)
			}
		})
	}
}

func testAssetLogin(t *testing.T) {
	tests := map[string]struct {
		invalid bool
		method  string
		token   string
		heading string
	}{
		"required":      {method: "GET", token: "xsrf-cookie-value", heading: "403 Authentication Required"},
		"invalid":       {method: "POST", invalid: true, token: "xsrf-cookie-value", heading: "403 Invalid Password"},
		"escaped_token": {method: "GET", token: `"><script>bad()</script>`, heading: "403 Authentication Required"},
		"head":          {method: "HEAD", token: "xsrf-cookie-value"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequestWithContext(t.Context(), test.method, "/", nil)
			response := httptest.NewRecorder()
			if err := RenderLogin(response, request, test.invalid, test.token); err != nil {
				t.Fatal(err)
			}
			if response.Code != 403 {
				t.Fatalf("login status = %d", response.Code)
			}
			if test.method == "HEAD" {
				if response.Body.Len() != 0 {
					t.Errorf("HEAD login body = %q", response.Body.String())
				}
				return
			}
			body := response.Body.String()
			for _, want := range []string{test.heading, `<form method="POST">`, `name="token"`, `name="_xsrf"`, `value="` + html.EscapeString(test.token) + `"`} {
				if !strings.Contains(body, want) {
					t.Errorf("login form missing %q: %s", want, body)
				}
			}
			if strings.Contains(body, "<script>") {
				t.Error("login form contains unescaped script markup")
			}
		})
	}
	t.Run("write_error", func(t *testing.T) {
		request := httptest.NewRequestWithContext(t.Context(), "GET", "/", nil)
		want := errors.New("closed response")
		response := assetErrorWriter{ResponseRecorder: httptest.NewRecorder(), err: want}
		if err := RenderLogin(response, request, false, "xsrf"); !errors.Is(err, want) {
			t.Errorf("login write error = %v, want %v", err, want)
		}
	})
}

type assetErrorWriter struct {
	*httptest.ResponseRecorder
	err error
}

func (w assetErrorWriter) Write([]byte) (int, error) { return 0, w.err }
