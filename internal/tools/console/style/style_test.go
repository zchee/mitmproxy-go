// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package style

import (
	"slices"
	"strings"
	"testing"

	lipgloss "charm.land/lipgloss/v2"
	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/contentviews/highlight"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
)

func TestConsoleFormatting(t *testing.T) {
	t.Run("upstream", func(t *testing.T) {
		tests := map[string]struct{}{"test_format_flow": {}, "test_format_durations": {}, "test_format_keyvals": {}, "test_truncated_text": {}}
		for name := range tests {
			t.Run(name, func(t *testing.T) {
				switch name {
				case "test_format_flow":
					for _, f := range testflow.TFlows() {
						for _, layout := range []string{"list", "table", "detailview", "default"} {
							for _, focused := range []bool{true, false} {
								for _, width := range []int{0, 10, 80, 100, 200} {
									r := FormatFlow(f, layout, !focused, width, focused)
									if r.ID != f.Common().ID || r.Type != f.Type() || (width >= 80 && strings.TrimSpace(r.Text) == "") {
										t.Fatalf("%T layout=%s width=%d focus=%v: %+v", f, layout, width, focused, r)
									}
									for line := range strings.SplitSeq(r.Text, "\n") {
										if Width(line) != width {
											t.Fatalf("%T %s: width %d != %d: %q", f, layout, Width(line), width, line)
										}
									}
								}
							}
						}
					}
					f := testflow.TFlow(testflow.WithResponse)
					f.Request.Headers.Set("Host", "display.example")
					f.Metadata.Set("h2-pushed-stream", true)
					f.Response.RawContent = nil
					r := FormatFlow(f, "list", true, 200, true)
					if !r.PushPromise || !r.ContentMissing || r.Host != "display.example" || !strings.Contains(r.Text, "PUSH_PROMISE") || !strings.Contains(r.Text, "[content missing]") {
						t.Fatalf("HTTP projection: %+v", r)
					}
					f.Response.RawContent = []byte{}
					if !strings.Contains(FormatFlow(f, "list", false, 200, false).Text, "[no content]") {
						t.Fatal("empty response not distinguished")
					}
					for _, protocol := range []flow.Flow{testflow.TFlow(), testflow.TTCPFlow(), testflow.TUDPFlow(), testflow.TDNSFlow()} {
						protocol.Common().Error = flow.NewError("bad\x1b]52;c;payload\a")
						if strings.ContainsAny(FormatFlow(protocol, "list", false, 200, true).Text, "\x1b\a") {
							t.Fatal("flow error contains terminal control")
						}
					}
				case "test_format_durations":
					for seconds, want := range map[float64][2]string{-0.1: {"-100ms", "gradient_99"}, 0: {"0ms", "gradient_99"}, 0.1: {"100ms", "gradient_43"}, 100: {"100s", "gradient_00"}} {
						text, tag := FormatDuration(seconds)
						if diff := cmp.Diff(want, [2]string{text, tag}); diff != "" {
							t.Errorf("seconds=%g: %s", seconds, diff)
						}
					}
				case "test_format_keyvals":
					got := FormatKeyValues([]KeyValue{{"aa", "bb"}, {"cc", "dd"}, {"ee", ""}}, 0)
					if diff := cmp.Diff("aa  bb\ncc  dd\nee  ", got); diff != "" {
						t.Fatal(diff)
					}
					nested := FormatKeyValues([]KeyValue{{"aa", FormatKeyValues([]KeyValue{{"foo", "bar"}}, 0)}}, 0)
					if !strings.Contains(nested, "foo  bar") {
						t.Fatal(nested)
					}
				case "test_truncated_text":
					for _, text := range []string{"Half-width", "ＦＵＬＬ－ＷＩＤＴＨ"} {
						if got := Fit(text, 10); Width(got) != 10 {
							t.Fatalf("width=%d: %q", Width(got), got)
						}
					}
				}
			})
		}
	})
	t.Run("security", func(t *testing.T) {
		tests := map[string]struct{}{"control_fields": {}, "unicode_width": {}}
		for name := range tests {
			t.Run(name, func(t *testing.T) {
				if name == "control_fields" {
					verifyFlowRowStyles(t)
					palette, err := NewPalette("solarized_dark", true)
					if err != nil {
						t.Fatal(err)
					}
					for _, input := range []string{"\x1b[2Jurl", "\x1b]52;c;hidden\a", "\u009b2J", "bad\rline", "a\x00b"} {
						escaped := Escape(input)
						if strings.ContainsAny(escaped, "\x1b\u009b\r\a\x00") {
							t.Fatalf("control retained: %q", escaped)
						}
						if !strings.Contains(palette.Render("text", input), escaped) {
							t.Fatal("render lost escaped content")
						}
					}
				} else {
					tests := map[string]struct {
						text                   string
						cursor, previous, next int
					}{
						"combining":   {"aéb", 2, 1, 3},
						"family":      {"a👨‍👩‍👧b", 3, 1, 6},
						"at boundary": {"aéb", 3, 1, 4},
						"negative":    {"aéb", -10, 0, 1},
						"past end":    {"aéb", 50, 3, 4},
						"empty":       {"", 3, 0, 0},
					}
					for name, test := range tests {
						if got := PreviousGrapheme(test.text, test.cursor); got != test.previous {
							t.Errorf("%s previous=%d want %d", name, got, test.previous)
						}
						if got := NextGrapheme(test.text, test.cursor); got != test.next {
							t.Errorf("%s next=%d want %d", name, got, test.next)
						}
					}
					for _, text := range []string{"日本語", "ＦＵＬＬ", "é", "👨‍👩‍👧"} {
						for width := range 8 {
							if got := Fit(text, width); Width(got) != width {
								t.Fatalf("%q width %d -> %q (%d)", text, width, got, Width(got))
							}
						}
					}
				}
			})
		}
	})
}

func TestConsolePalettes(t *testing.T) {
	t.Run("upstream", func(t *testing.T) {
		t.Run("TestPalette", func(t *testing.T) {
			tests := map[string]struct{}{"test_helptext": {}, "test_has_tags": {}}
			for name := range tests {
				t.Run(name, func(t *testing.T) {
					for _, name := range Names() {
						for _, transparent := range []bool{false, true} {
							p, err := NewPalette(name, transparent)
							if err != nil {
								t.Fatal(err)
							}
							if len(p.Tags()) < 160 {
								t.Fatalf("incomplete palette %s", name)
							}
							for _, tag := range highlight.Tags() {
								if !slices.Contains(p.Tags(), tag) {
									t.Fatalf("missing tag %s", tag)
								}
							}
						}
					}
				})
			}
		})
	})
	t.Run("palettes", func(t *testing.T) {
		tests := map[string]struct{}{"lowlight": {}, "lowdark": {}, "light": {}, "dark": {}, "solarized_light": {}, "solarized_dark": {}}
		for name := range tests {
			t.Run(name, func(t *testing.T) {
				for _, mode := range []string{"transparent", "opaque"} {
					t.Run(mode, func(t *testing.T) {
						p, err := NewPalette(name, mode == "transparent")
						if err != nil {
							t.Fatal(err)
						}
						_, noBackground := p.Style("background").GetBackground().(lipgloss.NoColor)
						if mode == "transparent" && !noBackground {
							t.Fatal("transparent background is colored")
						}
						if mode == "opaque" && noBackground {
							t.Fatal("opaque background missing")
						}
						for i := range 100 {
							tag := "gradient_" + string(rune('0'+i/10)) + string(rune('0'+i%10))
							if !slices.Contains(p.Tags(), tag) {
								t.Fatal("gradient missing")
							}
						}
						if p.Style("heading").GetForeground() == nil {
							t.Fatal("semantic foreground missing")
						}
					})
				}
			})
		}
	})
}
