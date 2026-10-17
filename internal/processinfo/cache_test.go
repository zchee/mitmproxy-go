// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package processinfo

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestProcessIconCache(t *testing.T) {
	tests := map[string]struct{ run func(*testing.T) }{
		"caller_ownership": {run: func(t *testing.T) {
			cache := newIconCache(256, 16<<20)
			source := []byte("image")
			var calls int
			load := func(string) ([]byte, error) { calls++; return source, nil }
			first, err := cache.get("a", load)
			if err != nil {
				t.Fatal(err)
			}
			first[0], source[1] = 'X', 'X'
			second, err := cache.get("a", load)
			if err != nil || !bytes.Equal(second, []byte("image")) || calls != 1 {
				t.Fatalf("cache result = %q, %v, loads %d; want immutable image and one load", second, err, calls)
			}
		}},
		"path_lru_and_dedup": {run: func(t *testing.T) {
			cache := newIconCache(2, 10)
			load := func(string) ([]byte, error) { return []byte("same"), nil }
			for _, path := range []string{"a", "b", "a", "c"} {
				if _, err := cache.get(path, load); err != nil {
					t.Fatal(err)
				}
			}
			if len(cache.paths) != 2 || cache.paths["b"] != nil || len(cache.icons) != 1 || cache.bytes != 4 {
				t.Fatalf("LRU/dedup state: paths %v, icons %d, bytes %d", cache.paths, len(cache.icons), cache.bytes)
			}
			for _, icon := range cache.icons {
				if icon.refs != 2 {
					t.Fatalf("shared image refs = %d, want 2", icon.refs)
				}
			}
		}},
		"byte_eviction": {run: func(t *testing.T) {
			cache := newIconCache(256, 6)
			load := func(path string) ([]byte, error) { return []byte(path), nil }
			for _, path := range []string{"aaa", "bbb", "ccc"} {
				if _, err := cache.get(path, load); err != nil {
					t.Fatal(err)
				}
			}
			if cache.paths["aaa"] != nil || cache.bytes != 6 || len(cache.icons) != 2 {
				t.Fatalf("byte eviction: paths %v, bytes %d, icons %d", cache.paths, cache.bytes, len(cache.icons))
			}
		}},
		"retry_failure": {run: func(t *testing.T) {
			cache := newIconCache(2, 10)
			cause := errors.New("temporary failure")
			if _, err := cache.get("a", func(string) ([]byte, error) { return nil, cause }); !errors.Is(err, cause) {
				t.Fatalf("load error = %v, want cause", err)
			}
			if len(cache.paths) != 0 || len(cache.icons) != 0 || cache.bytes != 0 {
				t.Fatal("failed load changed cache")
			}
			if _, err := cache.get("a", func(string) ([]byte, error) { return []byte("ok"), nil }); err != nil {
				t.Fatalf("retry: %v", err)
			}
		}},
		"oversized_and_empty": {run: func(t *testing.T) {
			cache := newIconCache(2, maxPNGBytes+1)
			for _, data := range [][]byte{nil, make([]byte, maxPNGBytes+1)} {
				if _, err := cache.get("a", func(string) ([]byte, error) { return data, nil }); err == nil {
					t.Fatalf("accepted %d bytes", len(data))
				}
			}
			if len(cache.paths) != 0 {
				t.Fatal("invalid image cached")
			}
		}},
		"real_capacity": {run: func(t *testing.T) {
			cache := newIconCache(256, 16<<20)
			for index := range 257 {
				path := fmt.Sprint(index)
				if _, err := cache.get(path, func(string) ([]byte, error) { return []byte(path), nil }); err != nil {
					t.Fatal(err)
				}
			}
			if len(cache.paths) != 256 || cache.paths["0"] != nil {
				t.Fatalf("capacity = %d, oldest = %v", len(cache.paths), cache.paths["0"])
			}
		}},
		"concurrent_publish": {run: func(t *testing.T) {
			cache := newIconCache(256, 16<<20)
			var entered atomic.Int32
			ready := make(chan struct{})
			var workers sync.WaitGroup
			for range 16 {
				workers.Go(func() {
					got, err := cache.get("same", func(string) ([]byte, error) {
						if entered.Add(1) == 16 {
							close(ready)
						}
						select {
						case <-ready:
						case <-t.Context().Done():
							return nil, t.Context().Err()
						}
						return []byte("value"), nil
					})
					if err != nil || string(got) != "value" {
						t.Errorf("concurrent get = %q, %v", got, err)
					}
				})
			}
			workers.Wait()
			if len(cache.paths) != 1 || len(cache.icons) != 1 || cache.bytes != 5 {
				t.Fatalf("concurrent state: paths %d, icons %d, bytes %d", len(cache.paths), len(cache.icons), cache.bytes)
			}
		}},
		"loader_runs_unlocked": {run: func(t *testing.T) {
			cache := newIconCache(2, 10)
			_, err := cache.get("outer", func(string) ([]byte, error) {
				if !cache.mu.TryLock() {
					return nil, errors.New("cache mutex held while loading")
				}
				cache.mu.Unlock()
				return []byte("ok"), nil
			})
			if err != nil {
				t.Fatal(err)
			}
		}},
		"evict_shared_content_last_reference": {run: func(t *testing.T) {
			cache := newIconCache(2, 4)
			load := func(path string) ([]byte, error) {
				if path == "c" {
					return []byte("new!"), nil
				}
				return []byte("same"), nil
			}
			for _, path := range []string{"a", "b", "c"} {
				if _, err := cache.get(path, load); err != nil {
					t.Fatal(err)
				}
			}
			paths := make([]string, 0, len(cache.paths))
			for path := range cache.paths {
				paths = append(paths, path)
			}
			slices.Sort(paths)
			if diff := cmp.Diff([]string{"c"}, paths); diff != "" {
				t.Fatalf("paths after shared eviction (-want +got):\n%s", diff)
			}
			if len(cache.icons) != 1 || cache.bytes != 4 {
				t.Fatalf("retained unreferenced content: icons %d, bytes %d", len(cache.icons), cache.bytes)
			}
		}},
	}
	for name, test := range tests {
		t.Run(name, test.run)
	}
}
