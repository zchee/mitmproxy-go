// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package httpmsg

// HTTP status codes upstream names: the official codes plus nginx's 444 No
// Response and 499 Client Closed Request.
const (
	StatusContinue                      = 100
	StatusSwitching                     = 101
	StatusProcessing                    = 102
	StatusEarlyHints                    = 103
	StatusOk                            = 200
	StatusCreated                       = 201
	StatusAccepted                      = 202
	StatusNonAuthoritativeInformation   = 203
	StatusNoContent                     = 204
	StatusResetContent                  = 205
	StatusPartialContent                = 206
	StatusMultiStatus                   = 207
	StatusAlreadyReported               = 208
	StatusImUsed                        = 226
	StatusMultipleChoice                = 300
	StatusMovedPermanently              = 301
	StatusFound                         = 302
	StatusSeeOther                      = 303
	StatusNotModified                   = 304
	StatusUseProxy                      = 305
	StatusTemporaryRedirect             = 307
	StatusPermanentRedirect             = 308
	StatusBadRequest                    = 400
	StatusUnauthorized                  = 401
	StatusPaymentRequired               = 402
	StatusForbidden                     = 403
	StatusNotFound                      = 404
	StatusNotAllowed                    = 405
	StatusNotAcceptable                 = 406
	StatusProxyAuthRequired             = 407
	StatusRequestTimeout                = 408
	StatusConflict                      = 409
	StatusGone                          = 410
	StatusLengthRequired                = 411
	StatusPreconditionFailed            = 412
	StatusPayloadTooLarge               = 413
	StatusRequestUriTooLong             = 414
	StatusUnsupportedMediaType          = 415
	StatusRequestedRangeNotSatisfiable  = 416
	StatusExpectationFailed             = 417
	StatusImATeapot                     = 418
	StatusMisdirectedRequest            = 421
	StatusUnprocessableContent          = 422
	StatusLocked                        = 423
	StatusFailedDependency              = 424
	StatusTooEarly                      = 425
	StatusUpgradeRequired               = 426
	StatusPreconditionRequired          = 428
	StatusTooManyRequests               = 429
	StatusRequestHeaderFieldsTooLarge   = 431
	StatusUnavailableForLegalReasons    = 451
	StatusNoResponse                    = 444
	StatusClientClosedRequest           = 499
	StatusInternalServerError           = 500
	StatusNotImplemented                = 501
	StatusBadGateway                    = 502
	StatusServiceUnavailable            = 503
	StatusGatewayTimeout                = 504
	StatusHttpVersionNotSupported       = 505
	StatusVariantAlsoNegotiates         = 506
	StatusInsufficientStorageSpace      = 507
	StatusLoopDetected                  = 508
	StatusNotExtended                   = 510
	StatusNetworkAuthenticationRequired = 511
)

// statusText holds upstream's reason phrases, which differ from the
// standard library's in places (for example "Request Time-out").
var statusText = map[int]string{
	StatusContinue:                      "Continue",
	StatusSwitching:                     "Switching Protocols",
	StatusProcessing:                    "Processing",
	StatusEarlyHints:                    "Early Hints",
	StatusOk:                            "OK",
	StatusCreated:                       "Created",
	StatusAccepted:                      "Accepted",
	StatusNonAuthoritativeInformation:   "Non-Authoritative Information",
	StatusNoContent:                     "No Content",
	StatusResetContent:                  "Reset Content",
	StatusPartialContent:                "Partial Content",
	StatusMultiStatus:                   "Multi-Status",
	StatusAlreadyReported:               "Already Reported",
	StatusImUsed:                        "IM Used",
	StatusMultipleChoice:                "Multiple Choices",
	StatusMovedPermanently:              "Moved Permanently",
	StatusFound:                         "Found",
	StatusSeeOther:                      "See Other",
	StatusNotModified:                   "Not Modified",
	StatusUseProxy:                      "Use Proxy",
	StatusTemporaryRedirect:             "Temporary Redirect",
	StatusPermanentRedirect:             "Permanent Redirect",
	StatusBadRequest:                    "Bad Request",
	StatusUnauthorized:                  "Unauthorized",
	StatusPaymentRequired:               "Payment Required",
	StatusForbidden:                     "Forbidden",
	StatusNotFound:                      "Not Found",
	StatusNotAllowed:                    "Method Not Allowed",
	StatusNotAcceptable:                 "Not Acceptable",
	StatusProxyAuthRequired:             "Proxy Authentication Required",
	StatusRequestTimeout:                "Request Time-out",
	StatusConflict:                      "Conflict",
	StatusGone:                          "Gone",
	StatusLengthRequired:                "Length Required",
	StatusPreconditionFailed:            "Precondition Failed",
	StatusPayloadTooLarge:               "Payload Too Large",
	StatusRequestUriTooLong:             "Request-URI Too Long",
	StatusUnsupportedMediaType:          "Unsupported Media Type",
	StatusRequestedRangeNotSatisfiable:  "Requested Range not satisfiable",
	StatusExpectationFailed:             "Expectation Failed",
	StatusImATeapot:                     "I'm a teapot",
	StatusMisdirectedRequest:            "Misdirected Request",
	StatusUnprocessableContent:          "Unprocessable Content",
	StatusLocked:                        "Locked",
	StatusFailedDependency:              "Failed Dependency",
	StatusTooEarly:                      "Too Early",
	StatusUpgradeRequired:               "Upgrade Required",
	StatusPreconditionRequired:          "Precondition Required",
	StatusTooManyRequests:               "Too Many Requests",
	StatusRequestHeaderFieldsTooLarge:   "Request Header Fields Too Large",
	StatusUnavailableForLegalReasons:    "Unavailable For Legal Reasons",
	StatusNoResponse:                    "No Response",
	StatusClientClosedRequest:           "Client Closed Request",
	StatusInternalServerError:           "Internal Server Error",
	StatusNotImplemented:                "Not Implemented",
	StatusBadGateway:                    "Bad Gateway",
	StatusServiceUnavailable:            "Service Unavailable",
	StatusGatewayTimeout:                "Gateway Time-out",
	StatusHttpVersionNotSupported:       "HTTP Version not supported",
	StatusVariantAlsoNegotiates:         "Variant Also Negotiates",
	StatusInsufficientStorageSpace:      "Insufficient Storage Space",
	StatusLoopDetected:                  "Loop Detected",
	StatusNotExtended:                   "Not Extended",
	StatusNetworkAuthenticationRequired: "Network Authentication Required",
}

// StatusText returns upstream's reason phrase for code, or the empty string
// for an unknown code.
func StatusText(code int) string {
	return statusText[code]
}
