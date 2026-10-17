// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviews

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/shamaton/msgpack/v3/def"
	yaml "go.yaml.in/yaml/v4"
)

// MsgPack renders MessagePack data as YAML and encodes edited YAML back.
//
// The YAML representation follows the Rust view: scalars are resolved with
// the YAML 1.2 core rules, strings that would read back as another type are
// single-quoted, and map entries keep their wire order. MessagePack binary
// values, which the Rust view cannot display, use the standard !!binary tag so
// that they survive an edit as binary rather than becoming strings.
type MsgPack struct{}

var _ InteractiveView = MsgPack{}

// Name returns the view's selection name.
func (MsgPack) Name() string { return "MsgPack" }

// SyntaxHighlight returns the language of the rendered text.
func (MsgPack) SyntaxHighlight() string { return "yaml" }

// RenderPriority selects the view for MessagePack media types.
func (MsgPack) RenderPriority(_ []byte, metadata Metadata) float64 {
	switch metadata.ContentType {
	case "application/msgpack", "application/x-msgpack":
		return 1
	default:
		return 0
	}
}

// Prettify decodes one MessagePack value and renders it as YAML.
func (MsgPack) Prettify(data []byte, _ Metadata) (string, error) {
	return prettifyMsgpack(data, newViewBudget("MsgPack"))
}

// Reencode parses one YAML document and encodes it as MessagePack.
func (MsgPack) Reencode(prettified string, _ Metadata) ([]byte, error) {
	return reencodeMsgpack(prettified, newViewBudget("MsgPack"))
}

// prettifyMsgpack spends every stage of one rendering from the same budget.
func prettifyMsgpack(data []byte, budget *viewBudget) (string, error) {
	value, err := decodeMsgpackValue(data, budget)
	if err == nil {
		err = checkMsgpackYAMLValue(value, budget)
	}
	if err != nil {
		return "", fmt.Errorf("Failed to deserialize MsgPack: %w", err) //nolint:staticcheck // The Rust view's user-facing error.
	}
	node, err := msgpackYAMLNode(value, budget, 0)
	if err == nil {
		var text string
		text, err = dumpBoundedYAML(node, budget, yamlEmitOptions{})
		if err == nil {
			return text, nil
		}
	}
	return "", fmt.Errorf("Failed to convert to YAML: %w", err) //nolint:staticcheck // The Rust view's user-facing error.
}

// reencodeMsgpack spends every stage of one encoding from the same budget.
func reencodeMsgpack(text string, budget *viewBudget) ([]byte, error) {
	value, err := msgpackFromYAML(text, budget)
	if err != nil {
		return nil, fmt.Errorf("Invalid YAML: %w", err) //nolint:staticcheck // The Rust view's user-facing error.
	}
	data, err := encodeMsgpackValue(value, budget)
	if err != nil {
		return nil, fmt.Errorf("Failed to encode to MsgPack: %w", err) //nolint:staticcheck // The Rust view's user-facing error.
	}
	return data, nil
}

const msgpackYAMLStage = "MsgPack YAML"

var (
	errMsgpackInvalidString = errors.New("string is not valid UTF-8")
	errMsgpackDuplicateKey  = errors.New("duplicate map key")
)

// checkMsgpackYAMLValue rejects decoded values that have no YAML
// representation the Rust view would accept: strings that are not UTF-8 and
// maps with repeated keys.
func checkMsgpackYAMLValue(value msgpackValue, budget *viewBudget) error {
	if text, ok := value.Scalar.(string); ok && !utf8.ValidString(text) {
		return errMsgpackInvalidString
	}
	for _, element := range value.Elements {
		if err := checkMsgpackYAMLValue(element, budget); err != nil {
			return err
		}
	}
	for _, entry := range value.Entries {
		if err := checkMsgpackYAMLValue(entry.Key, budget); err != nil {
			return err
		}
		if err := checkMsgpackYAMLValue(entry.Value, budget); err != nil {
			return err
		}
	}
	if len(value.Entries) > 1 {
		return checkMsgpackKeys(value.Entries, budget)
	}
	return nil
}

// checkMsgpackKeys reports a repeated key using the equality of the Rust
// view's YAML values, so 1 and 1.0 differ while 0.0 and -0.0 are the same.
func checkMsgpackKeys(entries []msgpackPair, budget *viewBudget) error {
	seen := make(map[string]struct{}, len(entries))
	var key strings.Builder
	for _, entry := range entries {
		key.Reset()
		if err := writeMsgpackKey(&key, entry.Key, budget); err != nil {
			return err
		}
		if _, found := seen[key.String()]; found {
			return errMsgpackDuplicateKey
		}
		seen[key.String()] = struct{}{}
	}
	return nil
}

// writeMsgpackKey appends a prefix-free canonical form of value, reserving
// its bytes before writing them.
func writeMsgpackKey(key *strings.Builder, value msgpackValue, budget *viewBudget) error {
	var text string
	switch scalar := value.Scalar.(type) {
	case nil:
		array, mapping := msgpackContainer(value.Code)
		if !array && !mapping {
			text = "n;"
			break
		}
		if err := budget.chargeMaterialization(msgpackYAMLStage, 2); err != nil {
			return err
		}
		open, end := byte('['), byte(']')
		if mapping {
			open, end = '{', '}'
		}
		key.WriteByte(open)
		for _, element := range value.Elements {
			if err := writeMsgpackKey(key, element, budget); err != nil {
				return err
			}
		}
		for _, entry := range value.Entries {
			if err := writeMsgpackKey(key, entry.Key, budget); err != nil {
				return err
			}
			if err := writeMsgpackKey(key, entry.Value, budget); err != nil {
				return err
			}
		}
		key.WriteByte(end)
		return nil
	case bool:
		text = "b" + strconv.FormatBool(scalar) + ";"
	case string:
		length := strconv.Itoa(len(scalar))
		if err := budget.chargeMaterialization(msgpackYAMLStage, uint64(2+len(length)+len(scalar))); err != nil {
			return err
		}
		key.WriteByte('s')
		key.WriteString(length)
		key.WriteByte(':')
		key.WriteString(scalar)
		return nil
	case []byte:
		length := strconv.Itoa(len(scalar))
		if err := budget.chargeMaterialization(msgpackYAMLStage, uint64(2+len(length)+len(scalar))); err != nil {
			return err
		}
		key.WriteByte('x')
		key.WriteString(length)
		key.WriteByte(':')
		key.Write(scalar)
		return nil
	case float32:
		text = msgpackFloatKey(float64(scalar))
	case float64:
		text = msgpackFloatKey(scalar)
	default:
		number, negative, ok := msgpackInteger(scalar)
		if !ok {
			return fmt.Errorf("%s: unsupported scalar type", msgpackYAMLStage)
		}
		text = "u" + number + ";"
		if negative {
			text = "i" + number + ";"
		}
	}
	if err := budget.chargeMaterialization(msgpackYAMLStage, uint64(len(text))); err != nil {
		return err
	}
	key.WriteString(text)
	return nil
}

func msgpackFloatKey(value float64) string {
	switch {
	case math.IsNaN(value):
		return "fnan;"
	case value == 0:
		return "f0;"
	default:
		return "f" + strconv.FormatUint(math.Float64bits(value), 16) + ";"
	}
}

func msgpackIsArray(code byte) bool {
	array, _ := msgpackContainer(code)
	return array
}

func msgpackIsMap(code byte) bool {
	_, mapping := msgpackContainer(code)
	return mapping
}

// msgpackInteger formats any decoded integer width in decimal.
func msgpackInteger(scalar any) (text string, negative, ok bool) {
	switch v := scalar.(type) {
	case int8:
		return strconv.FormatInt(int64(v), 10), v < 0, true
	case int16:
		return strconv.FormatInt(int64(v), 10), v < 0, true
	case int32:
		return strconv.FormatInt(int64(v), 10), v < 0, true
	case int64:
		return strconv.FormatInt(v, 10), v < 0, true
	case int:
		return strconv.FormatInt(int64(v), 10), v < 0, true
	case uint8:
		return strconv.FormatUint(uint64(v), 10), false, true
	case uint16:
		return strconv.FormatUint(uint64(v), 10), false, true
	case uint32:
		return strconv.FormatUint(uint64(v), 10), false, true
	case uint64:
		return strconv.FormatUint(v, 10), false, true
	case uint:
		return strconv.FormatUint(uint64(v), 10), false, true
	}
	return "", false, false
}

func msgpackYAMLNode(value msgpackValue, budget *viewBudget, depth int) (*yaml.Node, error) {
	if err := budget.chargeNodes(msgpackYAMLStage, 1); err != nil {
		return nil, err
	}
	array, mapping := msgpackContainer(value.Code)
	if array || mapping {
		depth++
		if err := budget.checkDepth(msgpackYAMLStage, depth); err != nil {
			return nil, err
		}
		node := &yaml.Node{Kind: yaml.SequenceNode}
		children := len(value.Elements)
		if mapping {
			node.Kind = yaml.MappingNode
			children = 2 * len(value.Entries)
		}
		if err := budget.chargeMaterialization(msgpackYAMLStage, uint64(children)*uint64(reflect.TypeFor[*yaml.Node]().Size())); err != nil {
			return nil, err
		}
		node.Content = make([]*yaml.Node, 0, children)
		for _, element := range value.Elements {
			child, err := msgpackYAMLNode(element, budget, depth)
			if err != nil {
				return nil, err
			}
			node.Content = append(node.Content, child)
		}
		for _, entry := range value.Entries {
			if msgpackIsMap(entry.Key.Code) {
				// The Rust view's emitter cannot write a mapping as a key.
				return nil, errors.New("a mapping cannot be a mapping key")
			}
			key, err := msgpackYAMLNode(entry.Key, budget, depth)
			if err != nil {
				return nil, err
			}
			child, err := msgpackYAMLNode(entry.Value, budget, depth)
			if err != nil {
				return nil, err
			}
			node.Content = append(node.Content, key, child)
		}
		return node, nil
	}
	node := &yaml.Node{Kind: yaml.ScalarNode}
	switch scalar := value.Scalar.(type) {
	case nil:
		node.Value = "null"
	case bool:
		node.Value = strconv.FormatBool(scalar)
	case string:
		node.Value = scalar
		node.Style = yamlStringStyle(scalar)
	case []byte:
		size := uint64(base64.StdEncoding.EncodedLen(len(scalar)))
		if err := budget.chargeMaterialization(msgpackYAMLStage, size); err != nil {
			return nil, err
		}
		node.Tag = "!!binary"
		node.Value = base64.StdEncoding.EncodeToString(scalar)
		if node.Value == "" {
			node.Style = yaml.SingleQuotedStyle
		}
	case float32:
		// The Rust view widens single-precision values before display.
		node.Value = formatYAMLFloat(float64(scalar))
	case float64:
		node.Value = formatYAMLFloat(scalar)
	default:
		number, _, ok := msgpackInteger(scalar)
		if !ok {
			return nil, fmt.Errorf("%s: unsupported scalar type", msgpackYAMLStage)
		}
		node.Value = number
	}
	return node, nil
}

// yamlStringStyle picks the presentation the Rust view's YAML emitter
// uses: block literal for multi-line text, single quotes when the plain form
// would read back as null, a boolean or a number, or as an octal number under
// YAML 1.1 (a leading zero followed by digits), and otherwise the plainest
// style the emitter allows.
func yamlStringStyle(text string) yaml.Style {
	switch {
	case strings.Contains(text, "\n"):
		return yaml.LiteralStyle
	case yamlCoreScalarKind(text) != yamlCoreString || yamlDigitsButNotNumber(text):
		return yaml.SingleQuotedStyle
	default:
		return 0
	}
}

// formatYAMLFloat renders the shortest round-trip digits in the layout of the
// Rust view's float formatter: positional notation with a trailing ".0" for
// magnitudes in [1e-5, 1e16), exponent notation outside it.
func formatYAMLFloat(value float64) string {
	switch {
	case math.IsNaN(value):
		return ".nan"
	case math.IsInf(value, 1):
		return ".inf"
	case math.IsInf(value, -1):
		return "-.inf"
	case value == 0:
		if math.Signbit(value) {
			return "-0.0"
		}
		return "0.0"
	}
	var out strings.Builder
	if value < 0 {
		out.WriteByte('-')
		value = -value
	}
	mantissa, exponent, _ := strings.Cut(strconv.FormatFloat(value, 'e', -1, 64), "e")
	digits := strings.Replace(mantissa, ".", "", 1)
	scale, _ := strconv.Atoi(exponent)
	point := scale + 1
	length := len(digits)
	switch {
	case point >= length && point <= 16:
		out.WriteString(digits)
		out.WriteString(strings.Repeat("0", point-length))
		out.WriteString(".0")
	case point > 0 && point <= 16:
		out.WriteString(digits[:point])
		out.WriteByte('.')
		out.WriteString(digits[point:])
	case point > -5 && point <= 0:
		out.WriteString("0.")
		out.WriteString(strings.Repeat("0", -point))
		out.WriteString(digits)
	default:
		out.WriteByte(digits[0])
		if length > 1 {
			out.WriteByte('.')
			out.WriteString(digits[1:])
		}
		out.WriteByte('e')
		out.WriteString(strconv.Itoa(point - 1))
	}
	return out.String()
}

type yamlCoreKind uint8

const (
	yamlCoreString yamlCoreKind = iota
	yamlCoreNull
	yamlCoreBool
	yamlCoreInt
	yamlCoreFloat
)

// yamlCoreScalarKind classifies an untagged plain scalar the way the Rust
// view's YAML loader does: the YAML 1.2 core schema, with 0x, 0o and 0b
// integers in either sign and without digit separators.
func yamlCoreScalarKind(text string) yamlCoreKind {
	if _, ok := parseYAMLNull(text); ok {
		return yamlCoreNull
	}
	if _, ok := parseYAMLBool(text); ok {
		return yamlCoreBool
	}
	if _, _, _, ok := parseYAMLInteger(text); ok {
		return yamlCoreInt
	}
	if !yamlDigitsButNotNumber(text) {
		if _, ok := parseYAMLFloat(text); ok {
			return yamlCoreFloat
		}
	}
	return yamlCoreString
}

func parseYAMLNull(text string) (struct{}, bool) {
	switch text {
	case "", "~", "null", "Null", "NULL":
		return struct{}{}, true
	}
	return struct{}{}, false
}

func parseYAMLBool(text string) (value, ok bool) {
	switch text {
	case "true", "True", "TRUE":
		return true, true
	case "false", "False", "FALSE":
		return false, true
	}
	return false, false
}

// yamlDigitsButNotNumber reports a leading zero followed only by digits,
// which YAML 1.2 reads as a string.
func yamlDigitsButNotNumber(text string) bool {
	text = strings.TrimPrefix(strings.TrimPrefix(text, "-"), "+")
	if len(text) < 2 || text[0] != '0' {
		return false
	}
	for i := 1; i < len(text); i++ {
		if text[i] < '0' || text[i] > '9' {
			return false
		}
	}
	return true
}

// parseYAMLInt reads an integer literal that fits 64 bits: a non-negative
// value as unsigned and a negative one as signed two's-complement bits.
func parseYAMLInt(text string) (value uint64, negative, ok bool) {
	high, low, negative, ok := parseYAMLInteger(text)
	if !ok || high != 0 || negative && low > 1<<63 {
		return 0, false, false
	}
	if negative {
		return -low, true, true
	}
	return low, false, true
}

// yamlIntegerOutOfRange reports an integer literal that fits 128 bits but not
// 64, which the Rust view reads as an integer and then rejects.
func yamlIntegerOutOfRange(text string) bool {
	_, _, ok := parseYAMLInt(text)
	if ok {
		return false
	}
	_, _, _, ok = parseYAMLInteger(text)
	return ok
}

// parseYAMLInteger reads a decimal, 0x, 0o or 0b literal with an optional
// sign into a 128-bit magnitude. A negative magnitude is at most 2^127; a
// decimal with a leading zero is not an integer.
func parseYAMLInteger(text string) (high, low uint64, negative, ok bool) {
	rest := text
	if unsigned, found := strings.CutPrefix(text, "+"); found {
		rest = unsigned
	} else if signed, found := strings.CutPrefix(text, "-"); found {
		rest, negative = signed, true
	}
	base := 10
	for _, radix := range []struct {
		prefix string
		base   int
	}{{"0x", 16}, {"0o", 8}, {"0b", 2}} {
		if digits, found := strings.CutPrefix(rest, radix.prefix); found {
			rest, base = digits, radix.base
			break
		}
	}
	if base == 10 && yamlDigitsButNotNumber(text) {
		return 0, 0, false, false
	}
	high, low, ok = parseYAMLDigits(rest, base)
	if !ok || negative && (high > 1<<63 || high == 1<<63 && low != 0) {
		return 0, 0, false, false
	}
	return high, low, negative, true
}

func parseYAMLDigits(digits string, base int) (high, low uint64, ok bool) {
	if digits == "" {
		return 0, 0, false
	}
	for i := range len(digits) {
		digit, ok := yamlDigit(digits[i], base)
		if !ok {
			return 0, 0, false
		}
		overflow, scaledHigh := bits.Mul64(high, uint64(base))
		carryHigh, scaledLow := bits.Mul64(low, uint64(base))
		var carry uint64
		low, carry = bits.Add64(scaledLow, digit, 0)
		high, carry = bits.Add64(scaledHigh, carryHigh, carry)
		if overflow != 0 || carry != 0 {
			return 0, 0, false
		}
	}
	return high, low, true
}

func yamlDigit(c byte, base int) (uint64, bool) {
	var digit uint64
	switch {
	case c >= '0' && c <= '9':
		digit = uint64(c - '0')
	case c >= 'a' && c <= 'f':
		digit = uint64(c-'a') + 10
	case c >= 'A' && c <= 'F':
		digit = uint64(c-'A') + 10
	default:
		return 0, false
	}
	return digit, digit < uint64(base)
}

// parseYAMLFloat accepts the YAML special values and finite decimal numbers.
func parseYAMLFloat(text string) (float64, bool) {
	unpositive := text
	if rest, found := strings.CutPrefix(text, "+"); found {
		if strings.HasPrefix(rest, "+") || strings.HasPrefix(rest, "-") {
			return 0, false
		}
		unpositive = rest
	}
	switch unpositive {
	case ".inf", ".Inf", ".INF":
		return math.Inf(1), true
	}
	switch text {
	case "-.inf", "-.Inf", "-.INF":
		return math.Inf(-1), true
	case ".nan", ".NaN", ".NAN":
		// The quiet NaN with a clear sign and payload, as the Rust view writes it.
		return math.Float64frombits(0x7ff8000000000000), true
	}
	if !yamlDecimalFloat(unpositive) {
		return 0, false
	}
	value, err := strconv.ParseFloat(unpositive, 64)
	if err != nil || math.IsInf(value, 0) {
		return 0, false
	}
	return value, true
}

// yamlDecimalFloat matches [-+]?(digits[.digits?]|.digits)([eE][-+]?digits)?.
func yamlDecimalFloat(text string) bool {
	i := 0
	if i < len(text) && (text[i] == '+' || text[i] == '-') {
		i++
	}
	integer := 0
	for i < len(text) && text[i] >= '0' && text[i] <= '9' {
		i++
		integer++
	}
	fraction := 0
	if i < len(text) && text[i] == '.' {
		i++
		for i < len(text) && text[i] >= '0' && text[i] <= '9' {
			i++
			fraction++
		}
	}
	if integer == 0 && fraction == 0 {
		return false
	}
	if i < len(text) && (text[i] == 'e' || text[i] == 'E') {
		i++
		if i < len(text) && (text[i] == '+' || text[i] == '-') {
			i++
		}
		exponent := 0
		for i < len(text) && text[i] >= '0' && text[i] <= '9' {
			i++
			exponent++
		}
		if exponent == 0 {
			return false
		}
	}
	return i == len(text)
}

var errMsgpackIntegerRange = errors.New("integer is outside the 64-bit range")

// msgpackFromYAML loads at most one YAML document; no document encodes nil.
func msgpackFromYAML(text string, budget *viewBudget) (msgpackValue, error) {
	if err := budget.checkInput("YAML snapshot", uint64(len(text))); err != nil {
		return msgpackValue{}, err
	}
	documents, err := parseBoundedYAML([]byte(text), budget)
	if err != nil {
		return msgpackValue{}, err
	}
	switch len(documents) {
	case 0:
		return msgpackValue{Code: def.Nil}, nil
	case 1:
		return yamlMsgpackValue(documents[0], budget, 0)
	default:
		return msgpackValue{}, errors.New("more than one YAML document")
	}
}

func yamlMsgpackValue(node *yaml.Node, budget *viewBudget, depth int) (msgpackValue, error) {
	if err := budget.chargeNodes(msgpackYAMLStage, 1); err != nil {
		return msgpackValue{}, err
	}
	switch node.Kind {
	case yaml.DocumentNode:
		if len(node.Content) == 0 {
			return msgpackValue{Code: def.Nil}, nil
		}
		return yamlMsgpackValue(node.Content[0], budget, depth)
	case yaml.AliasNode:
		if node.Alias == nil {
			return msgpackValue{}, errors.New("undefined alias")
		}
		return yamlMsgpackValue(node.Alias, budget, depth)
	}
	if tag, local := yamlLocalTag(node); local {
		// The Rust view keeps a local tag as a one-entry map from the tag to
		// the value read as if untagged.
		if err := budget.checkDepth(msgpackYAMLStage, depth+1); err != nil {
			return msgpackValue{}, err
		}
		if err := budget.chargeMaterialization(msgpackYAMLStage, uint64(len(tag))); err != nil {
			return msgpackValue{}, err
		}
		inner := *node
		inner.Tag, inner.Style = "", node.Style&^yaml.TaggedStyle
		value, err := yamlMsgpackValue(&inner, budget, depth+1)
		if err != nil {
			return msgpackValue{}, err
		}
		key := msgpackValue{Code: def.Str32, Scalar: tag}
		return msgpackValue{Code: def.FixMap, Entries: []msgpackPair{{Key: key, Value: value}}}, nil
	}
	switch node.Kind {
	case yaml.ScalarNode:
		return yamlMsgpackScalar(node, budget)
	case yaml.SequenceNode, yaml.MappingNode:
		depth++
		if err := budget.checkDepth(msgpackYAMLStage, depth); err != nil {
			return msgpackValue{}, err
		}
		if node.Kind == yaml.SequenceNode {
			if err := budget.chargeMaterialization(msgpackYAMLStage, uint64(len(node.Content))*uint64(reflect.TypeFor[msgpackValue]().Size())); err != nil {
				return msgpackValue{}, err
			}
			value := msgpackValue{Code: def.FixArray, Elements: make([]msgpackValue, 0, len(node.Content))}
			for _, child := range node.Content {
				element, err := yamlMsgpackValue(child, budget, depth)
				if err != nil {
					return msgpackValue{}, err
				}
				value.Elements = append(value.Elements, element)
			}
			return value, nil
		}
		if len(node.Content)%2 != 0 {
			return msgpackValue{}, errors.New("incomplete mapping entry")
		}
		if err := budget.chargeMaterialization(msgpackYAMLStage, uint64(len(node.Content)/2)*uint64(reflect.TypeFor[msgpackPair]().Size())); err != nil {
			return msgpackValue{}, err
		}
		value := msgpackValue{Code: def.FixMap, Entries: make([]msgpackPair, 0, len(node.Content)/2)}
		for i := 0; i < len(node.Content); i += 2 {
			key, err := yamlMsgpackValue(node.Content[i], budget, depth)
			if err != nil {
				return msgpackValue{}, err
			}
			child, err := yamlMsgpackValue(node.Content[i+1], budget, depth)
			if err != nil {
				return msgpackValue{}, err
			}
			value.Entries = append(value.Entries, msgpackPair{Key: key, Value: child})
		}
		if err := checkMsgpackKeys(value.Entries, budget); err != nil {
			return msgpackValue{}, err
		}
		return value, nil
	}
	return msgpackValue{}, errors.New("unsupported YAML node")
}

// yamlLocalTag reports an explicit local tag such as !point, and the
// non-specific tag "!", which the Rust view names "!!". Standard tags and
// global tags are not local.
func yamlLocalTag(node *yaml.Node) (string, bool) {
	if node.Tag == "!" {
		return "!!", true
	}
	if node.Style&yaml.TaggedStyle == 0 || !strings.HasPrefix(node.Tag, "!") || strings.HasPrefix(node.Tag, "!!") {
		return "", false
	}
	return node.Tag, true
}

func yamlMsgpackScalar(node *yaml.Node, budget *viewBudget) (msgpackValue, error) {
	text := node.Value
	plain := node.Style&(yaml.SingleQuotedStyle|yaml.DoubleQuotedStyle|yaml.LiteralStyle|yaml.FoldedStyle) == 0
	kind := yamlCoreString
	if node.Style&yaml.TaggedStyle != 0 && node.Tag != "!" {
		switch node.Tag {
		case "!!null":
			if _, ok := parseYAMLNull(text); !ok || text == "" {
				return msgpackValue{}, errors.New("invalid value for !!null")
			}
			kind = yamlCoreNull
		case "!!bool":
			kind = yamlCoreBool
		case "!!int":
			kind = yamlCoreInt
		case "!!float":
			kind = yamlCoreFloat
		case "!!binary":
			return yamlMsgpackBinary(text, node.Style, budget)
		}
	} else if plain {
		kind = yamlCoreScalarKind(text)
	}
	switch kind {
	case yamlCoreNull:
		return msgpackValue{Code: def.Nil}, nil
	case yamlCoreBool:
		value, ok := parseYAMLBool(text)
		if !ok {
			return msgpackValue{}, errors.New("invalid value for !!bool")
		}
		code := byte(def.False)
		if value {
			code = def.True
		}
		return msgpackValue{Code: code, Scalar: value}, nil
	case yamlCoreInt:
		value, negative, ok := parseYAMLInt(text)
		if !ok {
			if yamlIntegerOutOfRange(text) {
				return msgpackValue{}, errMsgpackIntegerRange
			}
			return msgpackValue{}, errors.New("invalid value for !!int")
		}
		if negative {
			return msgpackValue{Code: def.Int64, Scalar: int64(value)}, nil //nolint:gosec // The bits came from a negative int64.
		}
		return msgpackValue{Code: def.Uint64, Scalar: value}, nil
	case yamlCoreFloat:
		value, ok := parseYAMLFloat(text)
		if !ok {
			return msgpackValue{}, errors.New("invalid value for !!float")
		}
		return msgpackValue{Code: def.Float64, Scalar: value}, nil
	}
	if err := budget.chargeMaterialization(msgpackYAMLStage, uint64(len(text))); err != nil {
		return msgpackValue{}, err
	}
	return msgpackValue{Code: def.Str32, Scalar: text}, nil
}

// yamlMsgpackBinary decodes standard base64. Only a literal or folded block
// scalar, whose lines the emitter wraps, has its whitespace removed first; a
// quoted or plain scalar keeps its bytes, so whitespace there is invalid.
// The decoder itself skips line breaks, so they are refused here.
func yamlMsgpackBinary(text string, style yaml.Style, budget *viewBudget) (msgpackValue, error) {
	compact := text
	if style&(yaml.LiteralStyle|yaml.FoldedStyle) == 0 && strings.ContainsAny(text, "\r\n") {
		return msgpackValue{}, errors.New("invalid base64 in !!binary value")
	}
	if style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
		compact = strings.Map(func(r rune) rune {
			if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
				return -1
			}
			return r
		}, text)
	}
	if err := budget.chargeMaterialization(msgpackYAMLStage, uint64(base64.StdEncoding.DecodedLen(len(compact)))); err != nil {
		return msgpackValue{}, err
	}
	data, err := base64.StdEncoding.DecodeString(compact)
	if err != nil {
		return msgpackValue{}, errors.New("invalid base64 in !!binary value")
	}
	return msgpackValue{Code: def.Bin32, Scalar: data}, nil
}
