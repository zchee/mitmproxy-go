// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build !clipboard

package export

import (
	"context"

	"github.com/zchee/mitmproxy-go/command"
)

func copyClipboard(context.Context, []byte) error {
	return &command.Error{Msg: "export.clip: clipboard support is not compiled in (build with -tags clipboard)"}
}
