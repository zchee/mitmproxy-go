// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package style

import (
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"

	lipgloss "charm.land/lipgloss/v2"
)

// Palette holds the translated upstream semantic and gradient styles.
type Palette struct {
	Name        string
	Transparent bool
	styles      map[string]lipgloss.Style
}

// Names returns the six supported palette names in sorted order.
func Names() []string {
	return []string{"dark", "light", "lowdark", "lowlight", "solarized_dark", "solarized_light"}
}

// NewPalette selects a palette and applies its transparent-background policy.
func NewPalette(name string, transparent bool) (Palette, error) {
	if !slices.Contains(Names(), name) {
		return Palette{}, fmt.Errorf("unknown console palette %q", name)
	}
	low := parseColors(lowDark)
	if name == "light" || name == "lowlight" || name == "solarized_light" {
		low = parseColors(lowLight)
	}
	high := map[string][2]string{}
	switch name {
	case "dark":
		high = parseColors(highDark)
	case "light":
		high = parseColors(highLight)
	case "solarized_dark":
		high = parseColors(solarizedDark)
	case "solarized_light":
		high = parseColors(solarizedLight)
	}
	gradient := []string{"light_red", "yellow", "light_green", "dark_green", "dark_cyan", "dark_blue"}
	for i := range 100 {
		tag := fmt.Sprintf("gradient_%02d", i)
		low[tag] = [2]string{gradient[i*len(gradient)/100], "default"}
		if name == "solarized_dark" {
			points := [][3]int{{15, 0, 0}, {15, 15, 0}, {0, 15, 0}, {0, 15, 15}, {0, 0, 15}}
			position := float64(i) * 4 / 100
			index := int(position)
			fraction := position - float64(index)
			var rgb [3]int
			for c := range 3 {
				rgb[c] = int(math.RoundToEven(float64(points[index][c]) + float64(points[index+1][c]-points[index][c])*fraction))
			}
			high[tag] = [2]string{fmt.Sprintf("#%x%x%x", rgb[0], rgb[1], rgb[2]), "default"}
		}
	}
	background := low["background"][1]
	if value, ok := high["background"]; ok {
		background = value[1]
	}
	p := Palette{Name: name, Transparent: transparent, styles: make(map[string]lipgloss.Style, len(low))}
	for tag, pair := range low {
		if h, ok := high[tag]; ok {
			pair = h
		}
		if pair[1] == "default" && !transparent {
			pair[1] = background
		}
		if tag == "background" && transparent {
			pair = [2]string{"default", "default"}
		}
		style := lipgloss.NewStyle()
		fg, bold := strings.CutSuffix(pair[0], ",bold")
		if fg != "default" {
			style = style.Foreground(lipgloss.Color(colorValue(fg)))
		}
		if pair[1] != "default" {
			style = style.Background(lipgloss.Color(colorValue(pair[1])))
		}
		p.styles[tag] = style.Bold(bold)
	}
	return p, nil
}

// Tags returns all semantic and gradient tags in sorted order.
func (p Palette) Tags() []string {
	tags := make([]string, 0, len(p.styles))
	for tag := range p.styles {
		tags = append(tags, tag)
	}
	slices.Sort(tags)
	return tags
}

// Style returns a style for already-escaped text. Unknown tags are unstyled.
func (p Palette) Style(tag string) lipgloss.Style { return p.styles[tag] }

// Render escapes untrusted text before adding trusted palette styling.
func (p Palette) Render(tag, text string) string { return p.Style(tag).Render(Escape(text)) }

func parseColors(text string) map[string][2]string {
	result := map[string][2]string{}
	for line := range strings.SplitSeq(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 {
			result[fields[0]] = [2]string{fields[1], fields[2]}
		}
	}
	return result
}

func colorValue(color string) string {
	colors := map[string]string{"black": "0", "dark_red": "1", "dark_green": "2", "brown": "3", "dark_blue": "4", "dark_magenta": "5", "dark_cyan": "6", "light_gray": "7", "dark_gray": "8", "light_red": "9", "light_green": "10", "yellow": "11", "light_blue": "12", "light_magenta": "13", "light_cyan": "14", "white": "15"}
	if value, ok := colors[color]; ok {
		return value
	}
	if value, ok := strings.CutPrefix(color, "h"); ok {
		return value
	}
	if value, ok := strings.CutPrefix(color, "g"); ok {
		percent, _ := strconv.Atoi(value)
		level := int(math.Round(float64(percent) * 255 / 100))
		return fmt.Sprintf("#%02x%02x%02x", level, level, level)
	}
	return color
}

const lowDark = `background white black
title white,bold default
heading white dark_blue
heading_key light_cyan dark_blue
heading_inactive dark_gray light_gray
key light_cyan default
head white,bold default
text light_gray default
option_selected black light_gray
option_selected_key light_cyan light_gray
option_active light_red default
option_active_selected light_red light_gray
method_get light_green default
method_post brown default
method_delete light_red default
method_head dark_cyan default
method_put dark_red default
method_other dark_magenta default
method_http2_push dark_gray default
scheme_http dark_cyan default
scheme_https dark_green default
scheme_ws brown default
scheme_wss dark_magenta default
scheme_tcp dark_magenta default
scheme_udp dark_magenta default
scheme_dns dark_blue default
scheme_quic brown default
scheme_other dark_magenta default
url_punctuation light_gray default
url_domain white default
url_filename dark_cyan default
url_extension light_gray default
url_query_key white default
url_query_value light_gray default
content_none dark_gray default
content_text light_gray default
content_script dark_green default
content_media light_blue default
content_data brown default
content_raw dark_red default
content_other dark_magenta default
focus yellow default
code_200 dark_green default
code_300 light_blue default
code_400 light_red default
code_500 light_red default
code_other dark_red default
alert light_magenta default
warn brown default
error light_red default
header dark_cyan default
highlight white,bold default
intercept brown default
replay light_green default
mark light_red default
name dark_green default
string dark_blue default
number light_magenta default
boolean dark_magenta default
comment dark_gray default
from_client light_blue default
to_client light_red default
focusfield black light_gray
focusfield_error dark_red light_gray
field_error dark_red default
editfield white default
commander_command white,bold default
commander_invalid light_red default
commander_hint dark_gray default`

const lowLight = `background black white
title dark_magenta default
heading white black
heading_key dark_blue black
heading_inactive black light_gray
key dark_blue default
head black default
text dark_gray default
option_selected black light_gray
option_selected_key dark_blue light_gray
option_active light_red default
option_active_selected light_red light_gray
method_get dark_green default
method_post brown default
method_head dark_cyan default
method_put light_red default
method_delete dark_red default
method_other light_magenta default
method_http2_push light_gray default
scheme_http dark_cyan default
scheme_https light_green default
scheme_ws brown default
scheme_wss light_magenta default
scheme_tcp light_magenta default
scheme_udp light_magenta default
scheme_dns light_blue default
scheme_quic brown default
scheme_other light_magenta default
url_punctuation dark_gray default
url_domain dark_gray default
url_filename black default
url_extension dark_gray default
url_query_key light_blue default
url_query_value dark_blue default
content_none black default
content_text dark_gray default
content_script light_green default
content_media light_blue default
content_data brown default
content_raw light_red default
content_other light_magenta default
focus black default
code_200 dark_green default
code_300 light_blue default
code_400 dark_red default
code_500 dark_red default
code_other light_red default
error light_red default
warn brown default
alert light_magenta default
header dark_blue default
highlight black,bold default
intercept brown default
replay dark_green default
mark dark_red default
name dark_green default
string dark_blue default
number light_magenta default
boolean dark_magenta default
comment dark_gray default
from_client dark_blue default
to_client dark_red default
focusfield black light_gray
focusfield_error dark_red light_gray
field_error dark_red black
editfield black default
commander_command dark_magenta default
commander_invalid light_red default
commander_hint light_gray default`

const highDark = `heading_inactive g58 g11
intercept #f60 default
option_selected g85 g45
option_selected_key light_cyan g50
option_active_selected light_red g50`

const highLight = `background black g100
heading g99 #08f
heading_key #0ff,bold #08f
heading_inactive g35 g85
replay #0a0,bold default
option_selected black g85
option_selected_key dark_blue g85
option_active_selected light_red g85`

const solarizedLight = `background h241 h230
title h37 default
text h241 default
heading h254 h235
heading_key h33 h234
heading_inactive h234 h245
key h33 default
head h241 default
option_selected h234 h254
option_selected_key h33 h254
option_active h166 default
option_active_selected h166 h254
method_get h64 default
method_post h166 default
method_head h37 default
method_put h160 default
method_delete h160 default
method_other h125 default
method_http2_push light_gray default
scheme_http h37 default
scheme_https light_green default
scheme_ws h166 default
scheme_wss light_magenta default
scheme_tcp light_magenta default
scheme_udp light_magenta default
scheme_dns light_blue default
scheme_quic h166 default
scheme_other light_magenta default
url_punctuation dark_gray default
url_domain dark_gray default
url_filename black default
url_extension dark_gray default
url_query_key h33 default
url_query_value dark_blue default
focus h240 default
code_200 h64 default
code_300 h33 default
code_400 h166 default
code_500 h160 default
code_other h125 default
error h160 default
warn h166 default
alert h125 default
header h33 default
highlight h240 default
intercept h160 default
replay h64 default
mark h240 default
name h64 default
string h37 default
number h33 default
boolean h125 default
comment h245 default
from_client h33 default
to_client h160 default
focusfield h241 h254
focusfield_error h160 h254
field_error h160 default
editfield h240 default
commander_command h37 default
commander_invalid h166 default
commander_hint h245 default`

const solarizedDark = `background h254 h234
title h33 default
text h245 default
heading h254 h240
heading_key h33,bold h240
heading_inactive h245 h235
key h33 default
head h254 default
option_selected h234 h241
option_selected_key h33 h241
option_active h166 default
option_active_selected h166 h241
focus h245 default
method_get h64 default
method_post h166 default
method_delete h160 default
method_head h37 default
method_put h160 default
method_other h125 default
method_http2_push h240 default
url_punctuation h242 default
url_domain h252 default
url_filename h132 default
url_extension h96 default
url_query_key h37 default
url_query_value h30 default
content_none h240 default
content_text h245 default
content_media h33 default
code_200 h64 default
code_300 h33 default
code_400 h166 default
code_500 h160 default
code_other h125 default
error h160 default
warn h166 default
alert h125 default
header h33 default
highlight h240 default
intercept h160 default
replay h64 default
mark h240 default
name h64 default
string h37 default
number h33 default
boolean h125 default
comment h241 default
from_client h33 default
to_client h160 default
focusfield h244 h235
focusfield_error h160 h235
field_error h160 default
editfield h245 default
commander_command h33 default
commander_invalid h166 default
commander_hint h241 default`
