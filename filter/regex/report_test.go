// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package regex

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestMatchStringReport(t *testing.T) {
	previous := logger.Load()
	t.Cleanup(func() { logger.Store(previous) })
	var logs atomic.Int64
	SetLogger(func(string, error) { logs.Add(1) })
	tests := map[string]struct {
		pattern string
		input   string
		limit   time.Duration
		want    [2]bool
	}{
		"success: RE2 match ignores timeout": {pattern: "a+", input: "aaa", limit: -time.Second, want: [2]bool{true, false}},
		"success: RE2 miss never abandoned":  {pattern: "a+", input: "bbb", limit: -time.Second},
		"success: fallback match":            {pattern: "(?=a)a", input: "a", limit: 10 * time.Second, want: [2]bool{true, false}},
		"success: fallback miss":             {pattern: "(?=a)a", input: "b", limit: 10 * time.Second},
		"success: fallback abandoned":        {pattern: "(?=a)(a+)+$", input: strings.Repeat("a", 1000) + "!", limit: time.Nanosecond, want: [2]bool{false, true}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m, err := Compile(tt.pattern, 0)
			if err != nil {
				t.Fatal(err)
			}
			matched, abandoned := MatchStringReportTimeout(m, tt.input, tt.limit)
			if diff := gocmp.Diff(tt.want, [2]bool{matched, abandoned}); diff != "" {
				t.Errorf("report mismatch (-want +got):\n%s", diff)
			}
			if !tt.want[1] {
				matched, abandoned = MatchStringReport(m, tt.input)
				if diff := gocmp.Diff(tt.want, [2]bool{matched, abandoned}); diff != "" {
					t.Errorf("default report mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
	if got := logs.Load(); got != 0 {
		t.Errorf("reporting matches logged %d times, want none", got)
	}
}

func TestMatchStringReportConcurrent(t *testing.T) {
	m, err := Compile("(?i)(?=a)a", 0)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 16 {
				matched, abandoned := MatchStringReportTimeout(m, "A", 10*time.Second)
				if !matched || abandoned {
					t.Errorf("custom report = (%v, %v), want (true, false)", matched, abandoned)
				}
				if !m.MatchString("A") {
					t.Error("shared match failed")
				}
				matched, abandoned = MatchStringReport(m, "A")
				if !matched || abandoned {
					t.Errorf("default report = (%v, %v), want (true, false)", matched, abandoned)
				}
			}
		})
	}
	wg.Wait()
}
