// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package web

import (
 "log/slog"
 "net/http"

 "github.com/zchee/mitmproxy-go/internal/tools/web/webauth"
)

func (a *application) useAuth(auth *webauth.WebAuth) {
 a.firstFile = webauth.FirstUploadedFile
 a.protect = func(next http.Handler, index bool) http.Handler {
  var login webauth.LoginRenderer
  if index {
   login = func(w http.ResponseWriter, r *http.Request, data webauth.LoginData) {
    if err := RenderLogin(w, r, data.InvalidPassword, data.XSRFToken); err != nil {
     slog.ErrorContext(r.Context(), "Could not render web login", "error", err)
    }
   }
  }
  return auth.Wrap(next, login)
 }
}
