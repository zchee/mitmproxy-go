// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package web

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
)

func testWebDebug(t *testing.T) {
	tests := map[string]struct{ enabled, api bool }{
		"on":                  {enabled: true},
		"off":                 {},
		"api_error_identical": {api: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m := newWebMaster(t)
			if err := m.Do(t.Context(), func(ctx context.Context) error {
				f := testflow.TFlow(testflow.WithResponse)
				f.ID = "42"
				m.View.Add(ctx, []flow.Flow{f})
				return m.Options.Update(ctx, map[string]any{"web_debug": !tt.enabled})
			}); err != nil {
				t.Fatal(err)
			}
			done := startWebMaster(t, m)
			setDebug := func(enabled bool) {
				t.Helper()
				if err := m.Do(t.Context(), func(ctx context.Context) error { return m.Options.Update(ctx, map[string]any{"web_debug": enabled}) }); err != nil {
					t.Fatal(err)
				}
			}
			read := func(path string) (int, string, string) {
				t.Helper()
				response := masterRequest(t, m, "GET", path, "", "master-test")
				body, err := io.ReadAll(response.Body)
				closeErr := response.Body.Close()
				if err != nil || closeErr != nil {
					t.Fatalf("read=%v close=%v", err, closeErr)
				}
				return response.StatusCode, response.Header.Get("Content-Type"), string(body)
			}
			if tt.api {
				for _, enabled := range []bool{false, true} {
					setDebug(enabled)
					status, media, body := read("/executable-icon")
					if status != 400 || media != "text/html; charset=UTF-8" || body != "Missing 'path' parameter." {
						t.Fatalf("APIError changed with debug=%t: status=%d type=%q body=%q", enabled, status, media, body)
					}
				}
			} else {
				setDebug(tt.enabled)
				status, media, body := read("/flows/42/request/content/raw?lines=not-for-debug-output")
				if status != 500 {
					t.Fatalf("generic error status=%d", status)
				}
				if tt.enabled {
					if media != "text/plain; charset=UTF-8" || !strings.HasPrefix(body, "HTTP 500: Internal Server Error\n") || !strings.Contains(body, ".go:") {
						t.Fatalf("missing Go frame trace: type=%q body=%q", media, body)
					}
					for _, forbidden := range []string{"not-for-debug-output", "master-test", "Authorization", "/flows/42", "0x"} {
						if strings.Contains(body, forbidden) {
							t.Fatalf("debug trace contains request/argument data %q", forbidden)
						}
					}
				} else if media != "text/html; charset=UTF-8" || body != "<html><title>500: Internal Server Error</title><body>500: Internal Server Error</body></html>" {
					t.Fatalf("default generic error changed: type=%q body=%q", media, body)
				}
			}
			stopWebMaster(t, m, done)
		})
	}
}
