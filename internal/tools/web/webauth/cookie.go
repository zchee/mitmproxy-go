// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package webauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func signCookie(secret []byte, name string, at time.Time) string {
	var value strings.Builder
	value.WriteString("2|")
	for _, field := range []string{"0", strconv.FormatInt(at.Unix(), 10), name, "eQ=="} {
		value.WriteString(strconv.Itoa(len(field)))
		value.WriteByte(':')
		value.WriteString(field)
		value.WriteByte('|')
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(value.String()))
	return value.String() + hex.EncodeToString(mac.Sum(nil))
}

func validCookie(secret []byte, name, value string, at time.Time) bool {
	rest, ok := strings.CutPrefix(value, "2|")
	if !ok {
		return false
	}
	var fields [4]string
	for i := range fields {
		length, after, found := strings.Cut(rest, ":")
		if !found {
			return false
		}
		n, err := strconv.ParseUint(length, 10, 64)
		if err != nil || n >= uint64(len(after)) || after[n] != '|' {
			return false
		}
		fields[i], rest = after[:n], after[n+1:]
	}
	if _, err := strconv.ParseInt(fields[0], 10, 64); err != nil {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(value[:len(value)-len(rest)]))
	if !hmac.Equal([]byte(rest), []byte(hex.EncodeToString(mac.Sum(nil)))) || fields[2] != name {
		return false
	}
	timestamp, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || float64(timestamp) < float64(at.Unix())+float64(at.Nanosecond())/1e9-31*86400 {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(fields[3])
	return err == nil && string(decoded) == "y"
}

func (auth *WebAuth) hasSession(r *http.Request, config *configuration) bool {
	if config == nil {
		return false
	}
	cookie, err := r.Cookie(cookieName(config))
	return err == nil && validCookie(auth.secret[:], cookieName(config), cookie.Value, auth.clock())
}

func (auth *WebAuth) setSession(w http.ResponseWriter, config *configuration) {
	at := auth.clock()
	http.SetCookie(w, &http.Cookie{
		Name: cookieName(config), Value: signCookie(auth.secret[:], cookieName(config), at),
		Path: "/", Expires: at.Add(400 * 24 * time.Hour), HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
}
