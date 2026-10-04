// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package options

import "context"

// Constants of mitmproxy's options module.
const (
	// ConfDir is the default configuration directory.
	ConfDir = "~/.mitmproxy"
	// ConfBasename is the base name of the CA files in the configuration
	// directory.
	ConfBasename = "mitmproxy"
	// ContentViewLinesCutoff is the default of the content_view_lines_cutoff
	// option.
	ContentViewLinesCutoff = 512
	// KeySize is the default of the key_size option.
	KeySize = 2048
)

// coreOptions are the options mitmproxy's Options class registers itself,
// in its registration order. The help texts are copied verbatim, including
// the indentation of upstream's triple-quoted strings, so that Add
// normalises them into exactly the text upstream shows.
var coreOptions = []struct {
	name string
	typ  Type
	def  any
	help string
}{
	{"server", TypeBool, true, `Start a proxy server. Enabled by default.`},
	{"showhost", TypeBool, false, `Use the Host header to construct URLs for display.

            This option is disabled by default because malicious apps may send misleading host headers to evade
            your analysis. If this is not a concern, enable this options for better flow display.`},
	{"show_ignored_hosts", TypeBool, false, `
            Record ignored flows in the UI even if we do not perform TLS interception.
            This option will keep ignored flows' contents in memory, which can greatly increase memory usage.
            A future release will fix this issue, record ignored flows by default, and remove this option.
            `},
	{"add_upstream_certs_to_client_chain", TypeBool, false, `
            Add all certificates of the upstream server to the certificate chain
            that will be served to the proxy client, as extras.
            `},
	{"confdir", TypeStr, ConfDir, `Location of the default mitmproxy configuration files.`},
	{"certs", TypeSeq, []string{}, `
            SSL certificates of the form "[domain=]path". The domain may include
            a wildcard, and is equal to "*" if not specified. The file at path
            is a certificate in PEM format. If a private key is included in the
            PEM, it is used, else the default key in the conf dir is used. The
            PEM file should contain the full certificate chain, with the leaf
            certificate as the first entry.
            `},
	{"cert_passphrase", TypeOptStr, nil, `
            Passphrase for decrypting the private key provided in the --cert option.

            Note that passing cert_passphrase on the command line makes your passphrase visible in your system's
            process list. Specify it in config.yaml to avoid this.
            `},
	{"client_certs", TypeOptStr, nil, `Client certificate file or directory.`},
	{"ignore_hosts", TypeSeq, []string{}, `
            Ignore host and forward all traffic without processing it. In
            transparent mode, it is recommended to use an IP address (range),
            not the hostname. In regular mode, only SSL traffic is ignored and
            the hostname should be used. The supplied value is interpreted as a
            regular expression and matched on the ip or the hostname.
            `},
	{"allow_hosts", TypeSeq, []string{}, `Opposite of --ignore-hosts.`},
	{"listen_host", TypeStr, "", "Address to bind proxy server(s) to (may be overridden for individual modes, see `mode`)."},
	{"listen_port", TypeOptInt, nil, "Port to bind proxy server(s) to (may be overridden for individual modes, see `mode`). By default, the port is mode-specific. The default regular HTTP proxy spawns on port 8080."},
	{"mode", TypeSeq, []string{"regular"}, "\n            The proxy server type(s) to spawn. Can be passed multiple times.\n\n            Mitmproxy supports \"regular\" (HTTP), \"local\", \"transparent\", \"socks5\", \"reverse:SPEC\",\n            \"upstream:SPEC\", and \"wireguard[:PATH]\" proxy servers. For reverse and upstream proxy modes, SPEC\n            is host specification in the form of \"http[s]://host[:port]\". For WireGuard mode, PATH may point to\n            a file containing key material. If no such file exists, it will be created on startup.\n\n            You may append `@listen_port` or `@listen_host:listen_port` to override `listen_host` or `listen_port` for\n            a specific proxy mode. Features such as client playback will use the first mode to determine\n            which upstream server to use.\n            "},
	{"upstream_cert", TypeBool, true, `Connect to upstream server to look up certificate details.`},
	{"http2", TypeBool, true, `Enable/disable HTTP/2 support. HTTP/2 support is enabled by default.`},
	{"http2_ping_keepalive", TypeInt, 58, `
            Send a PING frame if an HTTP/2 connection is idle for more than
            the specified number of seconds to prevent the remote site from closing it.
            Set to 0 to disable this feature.
            `},
	{"http3", TypeBool, true, `Enable/disable support for QUIC and HTTP/3. Enabled by default.`},
	{"http_connect_send_host_header", TypeBool, true, `Include host header with CONNECT requests. Enabled by default.`},
	{"websocket", TypeBool, true, `Enable/disable WebSocket support. WebSocket support is enabled by default.`},
	{"rawtcp", TypeBool, true, `Enable/disable raw TCP connections. TCP connections are enabled by default. `},
	{"ssl_insecure", TypeBool, false, `Do not verify upstream server SSL/TLS certificates.

            If this option is enabled, certificate validation is skipped and mitmproxy itself will be vulnerable to
            TLS interception.`},
	{"ssl_verify_upstream_trusted_confdir", TypeOptStr, nil, `
            Path to a directory of trusted CA certificates for upstream server
            verification prepared using the c_rehash tool.
            `},
	{"ssl_verify_upstream_trusted_ca", TypeOptStr, nil, `Path to a PEM formatted trusted CA certificate.`},
	{"tcp_hosts", TypeSeq, []string{}, `
            Generic TCP SSL proxy mode for all hosts that match the pattern.
            Similar to --ignore-hosts, but SSL connections are intercepted.
            The communication contents are printed to the log in verbose mode.
            `},
	{"udp_hosts", TypeSeq, []string{}, `
            Generic UDP SSL proxy mode for all hosts that match the pattern.
            Similar to --ignore-hosts, but SSL connections are intercepted.
            The communication contents are printed to the log in verbose mode.
            `},
	{"content_view_lines_cutoff", TypeInt, ContentViewLinesCutoff, `
            Flow content view lines limit. Limit is enabled by default to
            speedup flows browsing.
            `},
	{"key_size", TypeInt, KeySize, `
            TLS key size for certificates and CA.
            `},
	{"protobuf_definitions", TypeOptStr, nil, `Path to a .proto file that's used to resolve Protobuf field names when pretty-printing.`},
	{"tcp_timeout", TypeInt, 600, `
            Timeout in seconds for inactive TCP connections. Connections will be closed after this period of inactivity.
            `},
}

// New returns a Manager with mitmproxy's core options registered.
func New() *Manager {
	m := NewManager()
	for _, o := range coreOptions {
		if err := m.Add(context.Background(), o.name, o.typ, o.def, o.help); err != nil {
			panic("options: invalid core option " + o.name + ": " + err.Error())
		}
	}
	return m
}
