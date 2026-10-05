// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tlsparse_test

import (
	"errors"
	"testing"

	"github.com/zchee/mitmproxy-go/tlsparse"
)

func TestClientHelloLimitBeforeRecordCompletion(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		data []byte
	}{
		"header in incomplete record": {
			data: mustHex(t, "160303ffff0100fffd"),
		},
		"header split across incomplete final record": {
			data: mustHex(t, "16030300020100160303fffffffd"),
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			for end := 0; end < len(tt.data); end++ {
				got, err := tlsparse.GetClientHello(tt.data[:end])
				if got != nil || err != nil {
					t.Fatalf("GetClientHello(data[:%d]) = %x, %v; want nil, nil before the length is known", end, got, err)
				}
			}
			if got, err := tlsparse.GetClientHello(tt.data); got != nil || !errors.Is(err, tlsparse.ErrTooLarge) {
				t.Errorf("GetClientHello = %x, %v; want nil, ErrTooLarge without waiting for the rest of the record", got, err)
			}
			if got, err := tlsparse.ParseClientHello(tt.data); got != nil || !errors.Is(err, tlsparse.ErrTooLarge) {
				t.Errorf("ParseClientHello = %v, %v; want nil, ErrTooLarge without waiting for the rest of the record", got, err)
			}
		})
	}
}
