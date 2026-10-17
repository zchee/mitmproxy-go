// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviewsdraft

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/zchee/mitmproxy-go/contentviews"
)

func zipFixture(t testing.TB, names []string, nonUTF8 bool) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for _, name := range names {
		file, err := writer.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store, NonUTF8: nonUTF8})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write([]byte("content")); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestZIP(t *testing.T) {
	t.Run("upstream", func(t *testing.T) {
		tests := map[string]func(*testing.T){
			"test_view_zip": func(t *testing.T) {
				names := []string{"normal.txt", "with spaces.txt", "dir/nested.txt", "file\nwith\nnewlines.txt", "unicode_文件.txt", "café.txt"}
				view := ZIP{yaml: &fixtureYAML{}}
				text, err := view.Prettify(zipFixture(t, names, false), contentviews.Metadata{ContentType: "application/zip"})
				if err != nil {
					t.Fatal(err)
				}
				for _, name := range []string{"normal.txt", "with spaces.txt", "dir/nested.txt", "newlines", "文件", "café"} {
					if !strings.Contains(text, name) {
						t.Errorf("listing lacks %q", name)
					}
				}
				if view.SyntaxHighlight() != "yaml" {
					t.Fatal("incorrect syntax highlight")
				}
			},
			"test_view_zip_empty": func(t *testing.T) {
				text, err := (ZIP{}).Prettify(zipFixture(t, nil, false), contentviews.Metadata{})
				if err != nil || text != "(empty zip file)" {
					t.Fatalf("empty ZIP=%q %v", text, err)
				}
			},
			"test_render_priority": func(t *testing.T) {
				view := ZIP{}
				if view.RenderPriority([]byte("data"), contentviews.Metadata{ContentType: "application/zip"}) != 1 || view.RenderPriority([]byte("data"), contentviews.Metadata{ContentType: "text/plain"}) != 0 || view.RenderPriority(nil, contentviews.Metadata{ContentType: "application/zip"}) != 0 {
					t.Fatal("ZIP priority mismatch")
				}
			},
		}
		for name, test := range tests {
			t.Run(name, test)
		}
	})
	t.Run("filename_encoding", func(t *testing.T) {
		tests := map[string]struct {
			name    string
			nonUTF8 bool
			want    string
		}{
			"cp437":                 {"caf\x82.txt", true, "café.txt"},
			"utf8_flagged":          {"café.txt", false, "café.txt"},
			"valid_utf8_flag_clear": {"é.txt", true, "├⌐.txt"},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				text, err := (ZIP{yaml: &fixtureYAML{}}).Prettify(zipFixture(t, []string{tt.name}, tt.nonUTF8), contentviews.Metadata{})
				if err != nil || text != "- "+tt.want+"\n" {
					t.Fatalf("decoded name=%q %v; want %q", text, err, tt.want)
				}
			})
		}
	})
}

func TestZIPPreflight(t *testing.T) {
	valid := zipFixture(t, []string{"a", "b"}, false)
	end := len(valid) - 22
	start := int(binary.LittleEndian.Uint32(valid[end+16 : end+20]))
	tests := map[string]struct {
		mutate func([]byte)
		budget viewBudget
	}{
		"forged low count and exhausted actual entries": {
			mutate: func(data []byte) { clear(data[end+8 : end+12]) },
			budget: viewBudget{view: "ZIP", nodes: maxViewNodes - 1},
		},
		"count mismatch": {mutate: func(data []byte) { clear(data[end+8 : end+12]) }},
		"truncated metadata": {mutate: func(data []byte) {
			binary.LittleEndian.PutUint16(data[start+28:start+30], 0xffff)
		}},
		"invalid UTF8 flag": {mutate: func(data []byte) {
			binary.LittleEndian.PutUint16(data[start+8:start+10], 0x800)
			data[start+46] = 0xff
		}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			data := bytes.Clone(valid)
			tt.mutate(data)
			calls := 0
			_, err := zipNames(data, &tt.budget, func(reader io.ReaderAt, size int64) (*zip.Reader, error) {
				calls++
				return zip.NewReader(reader, size)
			})
			if err == nil || calls != 0 {
				t.Fatalf("invalid directory constructed reader %d times, error=%v", calls, err)
			}
		})
	}
}

func TestZIPInsecurePath(t *testing.T) {
	data := zipFixture(t, []string{"../visible.txt"}, false)
	names, err := zipNames(data, &viewBudget{view: "ZIP"}, func(input io.ReaderAt, size int64) (*zip.Reader, error) {
		reader, err := zip.NewReader(input, size)
		if err != nil && !errors.Is(err, zip.ErrInsecurePath) {
			return nil, err
		}
		return reader, zip.ErrInsecurePath
	})
	if err != nil || len(names.Content) != 1 || names.Content[0].Value != "../visible.txt" {
		t.Fatalf("display-only path was rejected: %v %v", names, err)
	}
}

func TestZIP64Preflight(t *testing.T) {
	data := make([]byte, 56+20+22)
	binary.LittleEndian.PutUint32(data[:4], 0x06064b50)
	binary.LittleEndian.PutUint64(data[4:12], 44)
	binary.LittleEndian.PutUint32(data[56:60], 0x07064b50)
	binary.LittleEndian.PutUint32(data[72:76], 1)
	binary.LittleEndian.PutUint32(data[76:80], 0x06054b50)
	binary.LittleEndian.PutUint16(data[84:86], 0xffff)
	binary.LittleEndian.PutUint16(data[86:88], 0xffff)
	if count, err := preflightZIP(data, &viewBudget{view: "ZIP"}); err != nil || count != 0 {
		t.Fatalf("valid empty ZIP64: count=%d err=%v", count, err)
	}
	tests := map[string]struct{ offset int }{
		"end length":       {4},
		"directory size":   {40},
		"directory offset": {48},
		"locator offset":   {64},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			broken := bytes.Clone(data)
			binary.LittleEndian.PutUint64(broken[tt.offset:tt.offset+8], ^uint64(0))
			if _, err := preflightZIP(broken, &viewBudget{view: "ZIP"}); err == nil {
				t.Fatal("ZIP64 overflow accepted")
			}
		})
	}
}

func FuzzZIP(f *testing.F) {
	f.Add(zipFixture(f, []string{"normal.txt"}, false))
	f.Add(zipFixture(f, nil, false))
	f.Add([]byte("PK\x05\x06"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = zipNames(data, &viewBudget{view: "ZIP"}, zip.NewReader)
	})
}
