// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build !clipboard

package cut

import (
	"context"

	"github.com/zchee/mitmproxy-go/command"
)

func copyClipboard(context.Context, []byte) error {
	return &command.Error{Msg: "cut.clip: clipboard support is not compiled in (build with -tags clipboard)"}
}
