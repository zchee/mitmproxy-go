// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package webauth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const xsrfCookieName = "_mitmproxy_xsrf"

func decodeXSRF(value string) (token []byte, timestamp int64, valid bool) {
	version, rest, separated := strings.Cut(value, "|")
	versioned := separated && version != "" && version[0] >= '1' && version[0] <= '9'
	for _, c := range version {
		if c < '0' || c > '9' {
			versioned = false
		}
	}
	if versioned {
		if version != "2" {
			return nil, 0, false
		}
		fields := strings.Split(rest, "|")
		if len(fields) != 3 {
			return nil, 0, false
		}
		mask, err := hex.DecodeString(fields[0])
		if err != nil || len(mask) != 4 {
			return nil, 0, false
		}
		token, err = hex.DecodeString(fields[1])
		if err != nil {
			return nil, 0, false
		}
		timestamp, err = strconv.ParseInt(fields[2], 10, 64)
		if err != nil {
			return nil, 0, false
		}
		for i := range token {
			token[i] ^= mask[i%len(mask)]
		}
		return token, timestamp, true
	}
	token, err := hex.DecodeString(value)
	if err != nil {
		token = []byte(value)
	}
	return token, 0, true
}

func rawXSRF(r *http.Request, at time.Time) ([]byte, int64, bool, error) {
	if cookie, err := r.Cookie(xsrfCookieName); err == nil && cookie.Value != "" {
		token, timestamp, valid := decodeXSRF(cookie.Value)
		if valid {
			if !strings.HasPrefix(cookie.Value, "2|") {
				timestamp = at.Unix()
			}
			return token, timestamp, false, nil
		}
	}
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return nil, 0, false, err
	}
	return token[:], at.Unix(), true, nil
}

func maskXSRF(token []byte, timestamp int64) (string, error) {
	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return "", err
	}
	masked := make([]byte, len(token))
	for i := range token {
		masked[i] = token[i] ^ mask[i%len(mask)]
	}
	return "2|" + hex.EncodeToString(mask[:]) + "|" + hex.EncodeToString(masked) + "|" + strconv.FormatInt(timestamp, 10), nil
}

func (auth *WebAuth) xsrfToken(w http.ResponseWriter, r *http.Request, config *configuration) (string, error) {
	at := auth.clock()
	token, timestamp, fresh, err := rawXSRF(r, at)
	if err != nil {
		return "", err
	}
	value, err := maskXSRF(token, timestamp)
	if err != nil {
		return "", err
	}
	if fresh {
		cookie := &http.Cookie{Name: xsrfCookieName, Value: value, Path: "/", SameSite: http.SameSiteStrictMode}
		if auth.hasSession(r, config) {
			cookie.Expires = at.Add(30 * 24 * time.Hour)
		}
		http.SetCookie(w, cookie)
	}
	return value, nil
}

func (auth *WebAuth) checkXSRF(r *http.Request) error {
	input, err := argument(r, "_xsrf")
	if err != nil {
		return err
	}
	if input == "" {
		input = r.Header.Get("X-XSRFToken")
	}
	if input == "" {
		input = r.Header.Get("X-CSRFToken")
	}
	if input == "" {
		return errors.New("'_xsrf' argument missing from POST")
	}
	token, _, valid := decodeXSRF(input)
	if !valid || len(token) == 0 {
		return errors.New("'_xsrf' argument has invalid format")
	}
	expected, _, _, err := rawXSRF(r, auth.clock())
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(token, expected) != 1 {
		return errors.New("XSRF cookie does not match POST argument")
	}
	return nil
}
