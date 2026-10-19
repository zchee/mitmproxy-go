// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package webauth

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

// ErrVerifierBusy means that the process-wide Argon2 resource budget is full.
// Callers must report overload, not an incorrect password.
var ErrVerifierBusy = errors.New("web password verifier is busy")

const maxMemoryKiB = 262144

type passwordHash struct {
	variant     string
	memory      uint32
	time        uint32
	parallelism uint8
	salt        []byte
	digest      []byte
}

func parsePasswordHash(encoded string) (*passwordHash, error) {
	invalid := errors.New("invalid argon2 hash")
	if len(encoded) > 1024 {
		return nil, invalid
	}
	fields := strings.Split(encoded, "$")
	if len(fields) != 6 || fields[0] != "" || fields[1] != "argon2i" && fields[1] != "argon2id" || fields[2] != "v=19" {
		return nil, invalid
	}
	params := make(map[string]uint64, 3)
	for field := range strings.SplitSeq(fields[3], ",") {
		name, value, found := strings.Cut(field, "=")
		if !found || name != "m" && name != "t" && name != "p" || value == "" {
			return nil, invalid
		}
		if _, duplicate := params[name]; duplicate {
			return nil, invalid
		}
		for _, char := range value {
			if char < '0' || char > '9' {
				return nil, invalid
			}
		}
		number, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return nil, invalid
		}
		params[name] = number
	}
	m, t, p := params["m"], params["t"], params["p"]
	if len(params) != 3 || p < 1 || p > 16 || m < 8*p || m > maxMemoryKiB || t < 1 || t > 10 {
		return nil, invalid
	}
	// PHC uses canonical, unpadded standard base64. Strict also rejects nonzero
	// trailing bits; checking the alphabet rejects the decoder's ignored CR/LF.
	decoded := make([][]byte, 2)
	for i, field := range fields[4:] {
		for _, c := range field {
			if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/') {
				return nil, invalid
			}
		}
		value, err := base64.RawStdEncoding.Strict().DecodeString(field)
		minimum := 8
		if i == 1 {
			minimum = 16
		}
		if err != nil || len(value) < minimum || len(value) > 64 {
			return nil, invalid
		}
		decoded[i] = value
	}
	return &passwordHash{variant: fields[1], memory: uint32(m), time: uint32(t), parallelism: uint8(p), salt: decoded[0], digest: decoded[1]}, nil
}

// One budget covers every addon instance and configuration generation. A single
// lock reserves the memory and concurrency slots together without a wait queue.
var verifierBudget struct {
	sync.Mutex
	active int
	memory uint32
}

func reserveVerifier(ctx context.Context, memory uint32) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	verifierBudget.Lock()
	defer verifierBudget.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if verifierBudget.active >= 2 || memory > maxMemoryKiB-verifierBudget.memory {
		return ErrVerifierBusy
	}
	verifierBudget.active++
	verifierBudget.memory += memory
	return nil
}

func releaseVerifier(memory uint32) {
	verifierBudget.Lock()
	verifierBudget.active--
	verifierBudget.memory -= memory
	verifierBudget.Unlock()
}

func (hash *passwordHash) check(ctx context.Context, password string) (bool, error) {
	if err := reserveVerifier(ctx, hash.memory); err != nil {
		return false, err
	}
	defer releaseVerifier(hash.memory)
	var digest []byte
	if hash.variant == "argon2i" {
		digest = argon2.Key([]byte(password), hash.salt, hash.time, hash.memory, hash.parallelism, uint32(len(hash.digest)))
	} else {
		digest = argon2.IDKey([]byte(password), hash.salt, hash.time, hash.memory, hash.parallelism, uint32(len(hash.digest)))
	}
	// Derivation cannot be canceled. Keep the reservation until it completes,
	// even if the caller disconnects, then report cancellation instead of a match.
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(hash.digest, digest) == 1, nil
}
