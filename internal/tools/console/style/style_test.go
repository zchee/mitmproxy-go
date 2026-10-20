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
)

func TestConsoleFormatting(t *testing.T) {
	t.Run("upstream", func(t *testing.T) {
		tests := map[string]struct{}{"test_format_durations": {}, "test_format_keyvals": {}, "test_truncated_text": {}}
		for name := range tests {
			t.Run(name, func(t *testing.T) {
				switch name {
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
