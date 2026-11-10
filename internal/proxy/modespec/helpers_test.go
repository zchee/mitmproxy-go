// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modespec

import (
	"errors"
	"fmt"
	"reflect"
)

// ParseAs parses a specification for a particular mode value type, such as
// ParseAs[Socks5Mode]("socks5@1080"). M must be a concrete mode value type or
// Mode itself, not a pointer. A different mode name is rejected before its
// configuration is validated, matching upstream's subclass parse methods.
func ParseAs[M Mode](spec string) (M, error) {
	var zero M
	typ := reflect.TypeFor[M]()
	expected := ""
	if typ != reflect.TypeFor[Mode]() {
		if typ.Kind() != reflect.Struct {
			return zero, errors.New("ParseAs requires a concrete mode value type or Mode")
		}
		expected = zero.Name()
	}
	mode, err := parse(spec, expected)
	if err != nil {
		return zero, err
	}
	result, ok := mode.(M)
	if !ok {
		return zero, fmt.Errorf("unsupported mode type: %s", typ)
	}
	return result, nil
}
