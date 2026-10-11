// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build !windows

package freeport

import (
	"context"
	"errors"
	"syscall"
)

func pairPortDomain(context.Context) (pairDomain, error) { return pairDomain{}, nil }

func collisionPairBind(err error) bool { return errors.Is(err, syscall.EADDRINUSE) }

func retryablePairBind(err error) bool { return collisionPairBind(err) }
