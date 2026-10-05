// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package command

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/rangetable"
	"golang.org/x/text/unicode/runenames"

	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/emoji"
	"github.com/zchee/mitmproxy-go/internal/pyrepr"
	"github.com/zchee/mitmproxy-go/internal/strutil"
)

// Type is the identity of a command parameter or return type, the Go
// counterpart of an entry in mitmproxy's CommandTypes registry, together
// with that entry's parsing, completion and validation behaviour from
// mitmproxy's types module.
//
// Identities are compared with ==. The basic identities are the *Type
// variables of this package; a choice is a [ChoiceType] value and two choices
// are equal when they name the same options command. [SpaceType] and
// [UnknownType] appear only in [ParseResult] values: like their upstream
// counterparts they are not in the registry, so a parameter cannot have them
// and [Manager.ParsePartial] marks their tokens invalid ([SpaceType] tokens
// are valid by construction, without consulting the identity).
type Type interface {
	// Name returns the identity name, for example "Path" or "StrSeq".
	Name() string
	// Display returns the user-facing type name upstream prints in signature
	// help, for example "path" or "str[]".
	Display() string
	// Parse converts the command-line word s to the identity's Go value,
	// as mitmproxy's parse does. A [ChoiceType] or flow identity resolves
	// s through commands called on m with ctx, so inside a command it must
	// receive that command's context.
	Parse(ctx context.Context, m *Manager, s string) (any, error)
	// Completion returns the completion candidates for the prefix s.
	// The candidates need not extend s; completers filter them.
	Completion(ctx context.Context, m *Manager, s string) ([]string, error)
	// IsValid reports whether v is a value of this identity, as
	// mitmproxy's is_valid does on a command's return value.
	IsValid(ctx context.Context, m *Manager, v any) bool
}

// basicType is an identity bound to at most one Go type. A nil goType means
// the identity cannot appear in a command signature.
type basicType struct {
	name    string
	display string
	goType  reflect.Type

	parse    func(ctx context.Context, m *Manager, s string) (any, error)
	complete func(ctx context.Context, m *Manager, s string) ([]string, error)
	valid    func(ctx context.Context, m *Manager, v any) bool
}

// Name implements [Type].
func (t *basicType) Name() string { return t.name }

// Display implements [Type].
func (t *basicType) Display() string { return t.display }

// String returns the identity name.
func (t *basicType) String() string { return t.name }

// Parse implements [Type].
func (t *basicType) Parse(ctx context.Context, m *Manager, s string) (any, error) {
	return t.parse(ctx, m, s)
}

// Completion implements [Type].
func (t *basicType) Completion(ctx context.Context, m *Manager, s string) ([]string, error) {
	if t.complete == nil {
		return nil, nil
	}
	return t.complete(ctx, m, s)
}

// IsValid implements [Type].
func (t *basicType) IsValid(ctx context.Context, m *Manager, v any) bool {
	return t.valid(ctx, m, v)
}

// Go types for the identities that need a type of their own in a command
// signature. They mirror the annotation classes of mitmproxy.types.
type (
	// Path is a filesystem path argument.
	Path string

	// Cmd is the name of another command.
	Cmd string

	// CmdArgs is an argument passed through to the command named by a [Cmd]
	// parameter.
	CmdArgs string

	// Marker is a flow marker: "true", "false" or an emoji shortcode.
	Marker string

	// CutSpec is a list of flow attribute selectors for the cut addon, such
	// as "request.host" or "response.header[content-type]".
	CutSpec []string

	// Data is a table of rows whose cells are each a string or a []byte.
	Data [][]any
)

// The type identities registered with mitmproxy's CommandTypes, plus
// [SpaceType] and [UnknownType], which upstream defines outside the registry
// for [Manager.ParsePartial].
//
// FlowType binds to the [flow.Flow] interface and FlowsType to a slice of
// it, so a command takes one flow or a list of flows of any kind and may
// type-switch to the concrete flow it handles.
var (
	ArgType Type = &basicType{
		name: "Arg", display: "arg", goType: reflect.TypeFor[CmdArgs](),
		parse: func(_ context.Context, _ *Manager, s string) (any, error) { return CmdArgs(s), nil },
		valid: func(_ context.Context, _ *Manager, v any) bool { return isString(v) },
	}
	BoolType Type = &basicType{
		name: "Bool", display: "bool", goType: reflect.TypeFor[bool](),
		parse: func(_ context.Context, _ *Manager, s string) (any, error) {
			switch s {
			case "true":
				return true, nil
			case "false":
				return false, nil
			}
			return nil, fmt.Errorf("Booleans are 'true' or 'false', got %s", s) //nolint:staticcheck // mitmproxy's message, shown to users verbatim.
		},
		complete: func(context.Context, *Manager, string) ([]string, error) {
			return []string{"false", "true"}, nil
		},
		valid: func(_ context.Context, _ *Manager, v any) bool { _, ok := v.(bool); return ok },
	}
	BytesType Type = &basicType{
		name: "Bytes", display: "bytes", goType: reflect.TypeFor[[]byte](),
		parse: func(_ context.Context, _ *Manager, s string) (any, error) {
			return strutil.EscapedStrToBytes(s)
		},
		valid: func(_ context.Context, _ *Manager, v any) bool { _, ok := v.([]byte); return ok },
	}
	CmdType Type = &basicType{
		name: "Cmd", display: "cmd", goType: reflect.TypeFor[Cmd](),
		parse: func(_ context.Context, m *Manager, s string) (any, error) {
			if !m.has(s) {
				return nil, fmt.Errorf("Unknown command: %s", s) //nolint:staticcheck // mitmproxy's message, shown to users verbatim.
			}
			return Cmd(s), nil
		},
		complete: func(_ context.Context, m *Manager, _ string) ([]string, error) {
			var names []string
			for name := range m.Commands() {
				names = append(names, name)
			}
			return names, nil
		},
		valid: func(_ context.Context, m *Manager, v any) bool {
			s, ok := asString(v)
			return ok && m.has(s)
		},
	}
	CutSpecType Type = &basicType{
		name: "CutSpec", display: "cut[]", goType: reflect.TypeFor[CutSpec](),
		parse: func(_ context.Context, _ *Manager, s string) (any, error) {
			return CutSpec(strings.Split(s, ",")), nil
		},
		complete: func(_ context.Context, _ *Manager, s string) ([]string, error) {
			spec := strings.Split(s, ",")
			opts := make([]string, len(cutSpecPrefixes))
			for i, pref := range cutSpecPrefixes {
				spec[len(spec)-1] = pref
				opts[i] = strings.Join(spec, ",")
			}
			return opts, nil
		},
		// Like upstream, validation takes the textual spec, not the parsed
		// list: each comma-separated part must start with a known selector.
		valid: func(_ context.Context, _ *Manager, v any) bool {
			s, ok := asString(v)
			if !ok {
				return false
			}
			for part := range strings.SplitSeq(s, ",") {
				part = pyStrip(part)
				if !slices.ContainsFunc(cutSpecPrefixes, func(pref string) bool { return strings.HasPrefix(part, pref) }) {
					return false
				}
			}
			return true
		},
	}
	DataType Type = &basicType{
		name: "Data", display: "data[][]", goType: reflect.TypeFor[Data](),
		parse: func(context.Context, *Manager, string) (any, error) { return nil, errDataArgument },
		complete: func(context.Context, *Manager, string) ([]string, error) {
			return nil, errDataArgument
		},
		valid: func(_ context.Context, _ *Manager, v any) bool {
			d, ok := v.(Data)
			if !ok {
				return false
			}
			for _, row := range d {
				for _, cell := range row {
					switch cell.(type) {
					case string, []byte:
					default:
						return false
					}
				}
			}
			return true
		},
	}
	FlowType Type = &basicType{
		name: "Flow", display: "flow", goType: reflect.TypeFor[flow.Flow](),
		parse: func(ctx context.Context, m *Manager, s string) (any, error) {
			flows, err := resolveFlows(ctx, m, s)
			if err != nil {
				return nil, err
			}
			if len(flows) != 1 {
				return nil, fmt.Errorf("Command requires one flow, specification matched %d.", len(flows)) //nolint:staticcheck // mitmproxy's message, shown to users verbatim.
			}
			return flows[0], nil
		},
		complete: completeFlowSpec,
		valid:    func(_ context.Context, _ *Manager, v any) bool { return isFlow(v) },
	}
	FlowsType Type = &basicType{
		name: "Flows", display: "flow[]", goType: reflect.TypeFor[[]flow.Flow](),
		parse: func(ctx context.Context, m *Manager, s string) (any, error) {
			return resolveFlows(ctx, m, s)
		},
		complete: completeFlowSpec,
		valid: func(_ context.Context, _ *Manager, v any) bool {
			fs, ok := v.([]flow.Flow)
			if !ok {
				return false
			}
			for _, f := range fs {
				if !isFlow(f) {
					return false
				}
			}
			return true
		},
	}
	IntType Type = &basicType{
		name: "Int", display: "int", goType: reflect.TypeFor[int](),
		parse: func(_ context.Context, _ *Manager, s string) (any, error) { return pyInt(s) },
		valid: func(_ context.Context, _ *Manager, v any) bool { _, ok := v.(int); return ok },
	}
	MarkerType Type = &basicType{
		name: "Marker", display: "marker", goType: reflect.TypeFor[Marker](),
		parse: func(_ context.Context, _ *Manager, s string) (any, error) {
			switch s {
			case "true":
				return Marker(":default:"), nil
			case "false":
				return Marker(""), nil
			}
			if _, ok := emoji.Char(s); !ok {
				return nil, errInvalidChoice
			}
			return Marker(s), nil
		},
		complete: func(context.Context, *Manager, string) ([]string, error) {
			return slices.Clone(allMarkers()), nil
		},
		valid: func(_ context.Context, _ *Manager, v any) bool {
			s, ok := asString(v)
			if !ok {
				return false
			}
			if s == "true" || s == "false" {
				return true
			}
			_, ok = emoji.Char(s)
			return ok
		},
	}
	PathType Type = &basicType{
		name: "Path", display: "path", goType: reflect.TypeFor[Path](),
		parse: func(_ context.Context, _ *Manager, s string) (any, error) {
			return Path(expandUser(s)), nil
		},
		complete: func(_ context.Context, _ *Manager, s string) ([]string, error) {
			return pathCompletion(s), nil
		},
		valid: func(_ context.Context, _ *Manager, v any) bool { return isString(v) },
	}
	StrType Type = &basicType{
		name: "Str", display: "str", goType: reflect.TypeFor[string](),
		parse: func(_ context.Context, _ *Manager, s string) (any, error) { return pyUnescape(s) },
		valid: func(_ context.Context, _ *Manager, v any) bool { return isString(v) },
	}
	StrSeqType Type = &basicType{
		name: "StrSeq", display: "str[]", goType: reflect.TypeFor[[]string](),
		parse: func(_ context.Context, _ *Manager, s string) (any, error) {
			parts := strings.Split(s, ",")
			for i, p := range parts {
				parts[i] = pyStrip(p)
			}
			return parts, nil
		},
		valid: func(_ context.Context, _ *Manager, v any) bool { _, ok := v.([]string); return ok },
	}

	// SpaceType is the identity of a separator token in a [ParseResult]
	// (mitmproxy's types.Space).
	SpaceType Type = &basicType{
		name: "Space", display: "space",
		parse: func(_ context.Context, _ *Manager, s string) (any, error) { return s, nil },
		valid: func(context.Context, *Manager, any) bool { return false },
	}

	// UnknownType is the identity of a token beyond the called command's
	// parameters in a [ParseResult] (mitmproxy's types.Unknown).
	UnknownType Type = &basicType{
		name: "Unknown", display: "unknown",
		parse: func(_ context.Context, _ *Manager, s string) (any, error) { return s, nil },
		valid: func(context.Context, *Manager, any) bool { return false },
	}
)

// errInvalidChoice is mitmproxy's text for a value outside a closed set.
var errInvalidChoice = fmt.Errorf("Invalid choice.") //nolint:staticcheck // mitmproxy's message, shown to users verbatim.

// errDataArgument reports a Data identity used as a command-line argument.
var errDataArgument = fmt.Errorf("data cannot be passed as argument")

// cutSpecPrefixes are the selectors a cut specification may start with
// (mitmproxy's _CutSpecType.valid_prefixes).
var cutSpecPrefixes = []string{
	"request.method",
	"request.scheme",
	"request.host",
	"request.http_version",
	"request.port",
	"request.path",
	"request.url",
	"request.text",
	"request.content",
	"request.raw_content",
	"request.timestamp_start",
	"request.timestamp_end",
	"request.header[",
	"response.status_code",
	"response.reason",
	"response.text",
	"response.content",
	"response.timestamp_start",
	"response.timestamp_end",
	"response.raw_content",
	"response.header[",
	"client_conn.peername.port",
	"client_conn.peername.host",
	"client_conn.tls_version",
	"client_conn.sni",
	"client_conn.tls_established",
	"server_conn.address.port",
	"server_conn.address.host",
	"server_conn.ip_address.host",
	"server_conn.tls_version",
	"server_conn.sni",
	"server_conn.tls_established",
}

// flowSpecPrefixes are the completions of a flow specification (mitmproxy's
// _BaseFlowType.valid_prefixes: the view markers, then the filter tokens).
var flowSpecPrefixes = []string{
	"@all", "@focus", "@shown", "@hidden", "@marked", "@unmarked",
	"~q", "~s", "~a", "~hq", "~hs", "~b", "~bq", "~bs", "~t", "~d", "~m", "~u", "~c",
}

func completeFlowSpec(context.Context, *Manager, string) ([]string, error) {
	return slices.Clone(flowSpecPrefixes), nil
}

// resolveFlows resolves a flow specification through the view.flows.resolve
// command, as mitmproxy's flow types do. Without the view addon the command
// does not exist, and the error, which wraps [ErrUnknownCommand], says so.
func resolveFlows(ctx context.Context, m *Manager, spec string) ([]flow.Flow, error) {
	res, err := m.CallStrings(ctx, "view.flows.resolve", []string{spec})
	if err != nil {
		return nil, err
	}
	flows, ok := res.([]flow.Flow)
	if !ok {
		return nil, fmt.Errorf("view.flows.resolve returned %T, not a flow list", res)
	}
	return slices.Clone(flows), nil
}

// allMarkers returns mitmproxy's ALL_MARKERS: "true", "false" and every
// emoji shortcode, in that order.
var allMarkers = sync.OnceValue(func() []string {
	return append([]string{"true", "false"}, emoji.Names()...)
})

// isFlow rejects nil interface values and typed nil implementations.
func isFlow(v any) bool {
	f, ok := v.(flow.Flow)
	if !ok || f == nil {
		return false
	}
	rv := reflect.ValueOf(f)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return !rv.IsNil()
	default:
		return true
	}
}

// isString reports whether v is a string or one of this package's named
// string types, the values Python's isinstance(val, str) accepts for the
// corresponding annotation classes.
func isString(v any) bool {
	_, ok := asString(v)
	return ok
}

// asString returns the string value of v when v is a string or one of this
// package's named string types.
func asString(v any) (string, bool) {
	switch s := v.(type) {
	case string:
		return s, true
	case Path:
		return string(s), true
	case Cmd:
		return string(s), true
	case CmdArgs:
		return string(s), true
	case Marker:
		return string(s), true
	default:
		return "", false
	}
}

// pyStrip trims the characters Python's str.strip() trims: the code points
// of str.isspace, which include the separators U+001C to U+001F.
func pyStrip(s string) string {
	return strings.TrimFunc(s, isSpaceRune)
}

// pyInt parses decimal integers using Python's whitespace and Unicode digits.
// Results must fit the native int used by command signatures.
func pyInt(s string) (int, error) {
	t := strings.TrimSpace(s)
	t = strings.Map(func(r rune) rune {
		if r < utf8.RuneSelf || !unicode.Is(unicode15, r) {
			return r
		}
		for _, span := range unicode.Nd.R16 {
			if uint32(r) >= uint32(span.Lo) && uint32(r) <= uint32(span.Hi) && (uint32(r)-uint32(span.Lo))%uint32(span.Stride) == 0 {
				return '0' + (r-rune(span.Lo))/rune(span.Stride)%10
			}
		}
		for _, span := range unicode.Nd.R32 {
			if uint32(r) >= span.Lo && uint32(r) <= span.Hi && (uint32(r)-span.Lo)%span.Stride == 0 {
				return '0' + (r-rune(span.Lo))/rune(span.Stride)%10
			}
		}
		return r
	}, t)
	digits := strings.TrimLeft(t, "+-")
	ok := len(t)-len(digits) <= 1 && digits != "" && digits[0] != '_' && digits[len(digits)-1] != '_' && !strings.Contains(digits, "__") && len(digits)-strings.Count(digits, "_") <= 4300
	if ok {
		n, err := strconv.ParseInt(t[:len(t)-len(digits)]+strings.ReplaceAll(digits, "_", ""), 10, 0)
		if err == nil {
			return int(n), nil
		}
	}
	return 0, fmt.Errorf("invalid literal for int() with base 10: %s", pyrepr.Str(s))
}

// Python 3.13 uses Unicode 15.1. Its additions to 15.0 contain no decimal digits.
var unicode15 = rangetable.Assigned("15.0.0")

// escapeSequences matches the escape sequences a str argument decodes, the
// same set as mitmproxy's _StrType (Python string literal escapes).
const escapeSequences = `\\([\\'"abfnrtv]` +
	`|[0-7]{1,3}` + // character with octal value
	`|x..` + // character with hex value
	`|N\{[^}]+\}` + // character name in the Unicode database
	`|u....` + // character with 16-bit hex value
	`|U........` + // character with 32-bit hex value
	`)`

var escapeSequencesRE = sync.OnceValue(func() *regexp.Regexp { return regexp.MustCompile(escapeSequences) })

// pyUnescape decodes the escape sequences of a str command argument as
// mitmproxy does: each match of escapeSequences is decoded like a Python
// string literal and everything else is kept. A matched escape that does not
// decode, such as \xzz, \N{NO SUCH NAME} or a code point above U+10FFFF, is
// an error, as Python's unicode-escape codec raises. A surrogate escape such
// as \ud800 is an error too, where Python produces a lone surrogate that Go
// strings cannot hold (docs/compat.md).
func pyUnescape(s string) (string, error) {
	re := escapeSequencesRE()
	var decodeErr error
	out := re.ReplaceAllStringFunc(s, func(seq string) string {
		r, err := decodeEscape(seq)
		if err != nil && decodeErr == nil {
			decodeErr = err
		}
		return r
	})
	if decodeErr != nil {
		return "", decodeErr
	}
	return out, nil
}

// decodeEscape decodes one escape sequence, backslash included.
func decodeEscape(seq string) (string, error) {
	body := seq[1:]
	switch body[0] {
	case '\\', '\'', '"':
		return body, nil
	case 'a':
		return "\a", nil
	case 'b':
		return "\b", nil
	case 'f':
		return "\f", nil
	case 'n':
		return "\n", nil
	case 'r':
		return "\r", nil
	case 't':
		return "\t", nil
	case 'v':
		return "\v", nil
	case '0', '1', '2', '3', '4', '5', '6', '7':
		n, err := strconv.ParseUint(body, 8, 16)
		if err != nil {
			return "", fmt.Errorf("invalid octal escape %s", pyrepr.Str(seq))
		}
		return string(rune(n)), nil
	case 'x', 'u', 'U':
		n, err := strconv.ParseUint(body[1:], 16, 32)
		if err != nil {
			return "", fmt.Errorf("invalid %s escape %s", `\`+body[:1], pyrepr.Str(seq))
		}
		if n > utf8.MaxRune || (0xd800 <= n && n <= 0xdfff) {
			return "", fmt.Errorf("escape %s is not a representable code point", pyrepr.Str(seq))
		}
		return string(rune(n)), nil
	case 'N':
		name := body[2 : len(body)-1]
		for _, r := range name {
			if r >= utf8.RuneSelf {
				return "", fmt.Errorf("unknown Unicode character name %s", pyrepr.Str(name))
			}
		}
		key := strings.ToUpper(name)
		if r, ok := unicodeNameAliases[key]; ok {
			return string(r), nil
		}
		for _, block := range algorithmicNames {
			hex, found := strings.CutPrefix(key, block.prefix)
			if !found {
				continue
			}
			n, err := strconv.ParseUint(hex, 16, 32)
			if err == nil && n >= uint64(block.first) && n <= uint64(block.last) && strings.ToUpper(strconv.FormatUint(n, 16)) == hex {
				return string(rune(n)), nil
			}
		}
		r, ok := runeByName()[key]
		if !ok {
			return "", fmt.Errorf("unknown Unicode character name %s", pyrepr.Str(name))
		}
		return string(r), nil
	default:
		panic("unreachable: escapeSequences matched " + seq)
	}
}

// algorithmicNames are the hexadecimal name ranges from Unicode 15.1
// extracted/DerivedName.txt. Their names are not all present in runenames.
var algorithmicNames = [...]struct {
	first, last rune
	prefix      string
}{
	{0x3400, 0x4dbf, "CJK UNIFIED IDEOGRAPH-"},
	{0x4e00, 0x9fff, "CJK UNIFIED IDEOGRAPH-"},
	{0xf900, 0xfa6d, "CJK COMPATIBILITY IDEOGRAPH-"},
	{0xfa70, 0xfad9, "CJK COMPATIBILITY IDEOGRAPH-"},
	{0x17000, 0x187f7, "TANGUT IDEOGRAPH-"},
	{0x18b00, 0x18cd5, "KHITAN SMALL SCRIPT CHARACTER-"},
	{0x18d00, 0x18d08, "TANGUT IDEOGRAPH-"},
	{0x1b170, 0x1b2fb, "NUSHU CHARACTER-"},
	{0x20000, 0x2a6df, "CJK UNIFIED IDEOGRAPH-"},
	{0x2a700, 0x2b739, "CJK UNIFIED IDEOGRAPH-"},
	{0x2b740, 0x2b81d, "CJK UNIFIED IDEOGRAPH-"},
	{0x2b820, 0x2cea1, "CJK UNIFIED IDEOGRAPH-"},
	{0x2ceb0, 0x2ebe0, "CJK UNIFIED IDEOGRAPH-"},
	{0x2ebf0, 0x2ee5d, "CJK UNIFIED IDEOGRAPH-"},
	{0x2f800, 0x2fa1d, "CJK COMPATIBILITY IDEOGRAPH-"},
	{0x30000, 0x3134a, "CJK UNIFIED IDEOGRAPH-"},
	{0x31350, 0x323af, "CJK UNIFIED IDEOGRAPH-"},
}

// runeByName maps the formal names recognized by Python 3.13. Unicode 15.1
// adds three ranges to 15.0 (DerivedAge.txt); newer Go tables must not admit
// names that the Python oracle does not know.
var runeByName = sync.OnceValue(func() map[string]rune {
	m := make(map[string]rune)
	for r := rune(0); r <= utf8.MaxRune; r++ {
		assigned := unicode.Is(unicode15, r) || r >= 0x2ffc && r <= 0x2fff || r == 0x31ef || r >= 0x2ebf0 && r <= 0x2ee5d
		if !assigned {
			continue
		}
		name := runenames.Name(r)
		if r >= 0xac00 && r <= 0xd7a3 {
			// Unicode's Hangul syllable name algorithm concatenates the
			// leading consonant, vowel, and optional trailing consonant.
			leading := [...]string{"G", "GG", "N", "D", "DD", "R", "M", "B", "BB", "S", "SS", "", "J", "JJ", "C", "K", "T", "P", "H"}
			vowel := [...]string{"A", "AE", "YA", "YAE", "EO", "E", "YEO", "YE", "O", "WA", "WAE", "OE", "YO", "U", "WEO", "WE", "WI", "YU", "EU", "YI", "I"}
			trailing := [...]string{"", "G", "GG", "GS", "N", "NJ", "NH", "D", "L", "LG", "LM", "LB", "LS", "LT", "LP", "LH", "M", "B", "BS", "S", "SS", "NG", "J", "C", "K", "T", "P", "H"}
			i := r - 0xac00
			name = "HANGUL SYLLABLE " + leading[i/(21*28)] + vowel[i/28%21] + trailing[i%28]
		}
		if name == "" || name[0] == '<' {
			continue
		}
		if _, dup := m[name]; !dup {
			m[name] = r
		}
	}
	return m
})

// ChoiceType is a string parameter restricted to the values returned by
// another command.
type ChoiceType struct {
	// OptionsCommand names the command that returns the valid choices.
	OptionsCommand string
}

// Choice returns the identity of a string parameter whose valid values are
// returned by the command named optionsCommand. Attach it to a parameter
// with [WithArgument].
func Choice(optionsCommand string) Type {
	return ChoiceType{OptionsCommand: optionsCommand}
}

// Name implements [Type].
func (ChoiceType) Name() string { return "Choice" }

// Display implements [Type].
func (ChoiceType) Display() string { return "choice" }

// options returns the valid choices by executing the options command, as
// mitmproxy's _ChoiceType does.
func (t ChoiceType) options(ctx context.Context, m *Manager) ([]string, error) {
	res, err := m.Execute(ctx, t.OptionsCommand)
	if err != nil {
		return nil, err
	}
	opts, ok := res.([]string)
	if !ok {
		return nil, fmt.Errorf("%s returned %T, not the str[] a choice needs", t.OptionsCommand, res)
	}
	return opts, nil
}

// Parse implements [Type].
func (t ChoiceType) Parse(ctx context.Context, m *Manager, s string) (any, error) {
	opts, err := t.options(ctx, m)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(opts, s) {
		return nil, errInvalidChoice
	}
	return s, nil
}

// Completion implements [Type].
func (t ChoiceType) Completion(ctx context.Context, m *Manager, _ string) ([]string, error) {
	opts, err := t.options(ctx, m)
	return slices.Clone(opts), err
}

// IsValid implements [Type].
func (t ChoiceType) IsValid(ctx context.Context, m *Manager, v any) bool {
	s, ok := asString(v)
	if !ok {
		return false
	}
	opts, err := t.options(ctx, m)
	return err == nil && slices.Contains(opts, s)
}

// registryTypes are the identities in mitmproxy's CommandTypes registry.
// SpaceType and UnknownType are not: a token of those identities is never
// parseable.
var registryTypes = []Type{ArgType, BoolType, BytesType, CmdType, CutSpecType, DataType, FlowType, FlowsType, IntType, MarkerType, PathType, StrType, StrSeqType}

// inRegistry reports whether t is an entry of mitmproxy's CommandTypes
// registry, which SpaceType and UnknownType are not.
func inRegistry(t Type) bool {
	if t == nil || t == SpaceType || t == UnknownType {
		return false
	}
	return true
}

// byGoType maps each Go type a command signature may use to its identity.
var byGoType = func() map[reflect.Type]Type {
	m := make(map[reflect.Type]Type)
	for _, t := range registryTypes {
		m[t.(*basicType).goType] = t
	}
	return m
}()

// TypeFor returns the identity of the Go type rt, the type a command
// parameter or return value of that Go type is registered with. It returns
// an error wrapping [ErrSignature] when rt has no identity.
func TypeFor(rt reflect.Type) (Type, error) {
	if t, ok := byGoType[rt]; ok {
		return t, nil
	}
	return nil, fmt.Errorf("%w: unsupported type: %v", ErrSignature, rt)
}

// goTypeOf returns the Go type a parameter must have to carry the identity
// t, or nil when no parameter can.
func goTypeOf(t Type) reflect.Type {
	switch t := t.(type) {
	case *basicType:
		return t.goType
	case ChoiceType:
		return reflect.TypeFor[string]()
	default:
		return nil
	}
}
