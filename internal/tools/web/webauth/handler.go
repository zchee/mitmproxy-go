// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package webauth

import (
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"
)

// LoginData contains the values needed by the embedded login template.
type LoginData struct {
	InvalidPassword bool
	XSRFToken       string
}

// LoginRenderer writes the login page with status 403 and an HTML content type.
// Cookies are already pending in w.Header; it must not clear those headers.
type LoginRenderer func(w http.ResponseWriter, r *http.Request, data LoginData)

// Wrap protects an implemented API handler. Pass a login renderer only for the
// index route; other auth failures have upstream's empty 403 body. The caller
// owns route/method matching and static-service exemptions. It must call Wrap
// outside addon dispatch, because password derivation may be expensive.
func (auth *WebAuth) Wrap(next http.Handler, login LoginRenderer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !prepareArguments(w, r) {
			return
		}
		if r.MultipartForm != nil {
			defer func() { _ = r.MultipartForm.RemoveAll() }()
		}
		if unsafeMethod(r.Method) {
			if err := auth.checkXSRF(r); err != nil {
				writePolicyError(w, http.StatusForbidden)
				return
			}
			if site := r.Header.Get("Sec-Fetch-Site"); r.Header.Values("Sec-Fetch-Site") != nil && site != "same-origin" && site != "none" {
				writePolicyError(w, http.StatusForbidden)
				return
			}
		}
		if auth.authenticate(w, r, auth.config.Load(), login) {
			next.ServeHTTP(w, r)
		}
	})
}

// PrepareUpgrade applies the WebSocket handler's XSRF-cookie and auth policy.
// On success all Set-Cookie values are pending in w.Header. The updates adapter
// must copy them into the real 101 using gows response-header support; this
// method neither emits nor hijacks a handshake. On failure it writes HTTP 403
// (or 503 on verifier exhaustion) and the caller must not attempt an upgrade.
func (auth *WebAuth) PrepareUpgrade(w http.ResponseWriter, r *http.Request) bool {
	if !prepareArguments(w, r) {
		return false
	}
	if unsafeMethod(r.Method) {
		if err := auth.checkXSRF(r); err != nil {
			writePolicyError(w, http.StatusForbidden)
			return false
		}
	}
	config := auth.config.Load()
	if _, err := auth.xsrfToken(w, r, config); err != nil {
		writePolicyError(w, http.StatusInternalServerError)
		return false
	}
	return auth.authenticate(w, r, config, nil)
}

func (auth *WebAuth) authenticate(w http.ResponseWriter, r *http.Request, config *configuration, login LoginRenderer) bool {
	if auth.hasSession(r, config) {
		return true
	}
	var password string
	if scheme, params, _ := strings.Cut(r.Header.Get("Authorization"), " "); scheme == "Bearer" {
		password = params
	}
	if password == "" {
		var err error
		password, err = argument(r, "token")
		if err != nil {
			writePolicyError(w, http.StatusBadRequest)
			return false
		}
	}
	valid, err := checkPassword(r.Context(), config, password)
	if err != nil {
		if errors.Is(err, ErrVerifierBusy) {
			writePolicyError(w, http.StatusServiceUnavailable)
		}
		// A disconnected request has no response to deliver. In particular it
		// must never be converted into a wrong-password response or a cookie.
		return false
	}
	if !valid {
		if login != nil {
			xsrf, err := auth.xsrfToken(w, r, config)
			if err != nil {
				writePolicyError(w, http.StatusInternalServerError)
				return false
			}
			login(w, r, LoginData{InvalidPassword: password != "", XSRFToken: xsrf})
		} else {
			w.Header().Set("Content-Type", "text/html; charset=UTF-8")
			w.WriteHeader(http.StatusForbidden)
		}
		return false
	}
	auth.setSession(w, config)
	return true
}

func unsafeMethod(method string) bool {
	return method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
}

func prepareArguments(w http.ResponseWriter, r *http.Request) bool {
	if r.PostForm != nil {
		return true
	}
	mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaType != "application/x-www-form-urlencoded" && mediaType != "multipart/form-data" {
		return true
	}
	// Match the HTTP receive ceiling without ParseForm's implicit 10 MiB
	// limit. Multipart contents spill to owned temporary files, not to RAM.
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, 4<<30)
	}
	var err error
	if mediaType == "multipart/form-data" {
		err = r.ParseMultipartForm(32 << 20)
	} else {
		err = r.ParseForm()
	}
	if err != nil {
		writePolicyError(w, http.StatusBadRequest)
		return false
	}
	return true
}

func argument(r *http.Request, name string) (string, error) {
	// Tornado merges query arguments first, body arguments second, and selects
	// the final value. ParseForm's merged map has a different ordering.
	values := r.PostForm[name]
	if len(values) == 0 {
		values = r.URL.Query()[name]
	}
	if len(values) == 0 {
		return "", nil
	}
	value := values[len(values)-1]
	if !utf8.ValidString(value) {
		return "", errors.New("invalid unicode in argument")
	}
	value = strings.Map(func(char rune) rune {
		if char <= 8 || char >= 14 && char <= 31 {
			return ' '
		}
		return char
	}, value)
	return strings.TrimFunc(value, func(char rune) bool { return unicode.IsSpace(char) || char >= 0x1c && char <= 0x1f }), nil
}

func writePolicyError(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "<html><title>%d: %s</title><body>%d: %s</body></html>", status, http.StatusText(status), status, http.StatusText(status))
}
