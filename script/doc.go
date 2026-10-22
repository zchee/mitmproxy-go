// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package script embeds trusted operator-supplied Starlark addons. Register a
// Loader with the master's addon manager, supply the actual proxy listener
// addresses in Config, and call Loader.Close outside dispatch before log flush.
// Source and HTTP limits are safety bounds, not a CPU, memory, filesystem or
// network sandbox. A zero script_max_steps deliberately leaves evaluation
// unlimited; a positive budget meters interpreter steps, not Go builtin work.
//
// # Predeclared libraries
//
// Scripts receive ctx, module, concurrent, byteops, http and dns. Imports through
// load are unsupported. Ordinary hook names match the native addon interfaces,
// except load is spelled on_load because load is a Starlark keyword. A bounded
// acyclic addons list may contain module(name, **handlers) values.
//
// byteops.replace(data, old, new, count=-1) returns Bytes, and
// byteops.startswith(data, prefix) returns bool. All data arguments are Bytes.
// No process-global Starlark Universe entries are changed.
//
// http.Headers(fields=[]) accepts a mapping or an ordered name/value-pair
// sequence. Headers preserve case-insensitive ordering and duplicates. Indexed
// reads fold duplicate values; get(key, default=None), get_all(key),
// set_all(key, values), keys(), items(multi=False), pop(key, default=None) and
// the raw fields tuple expose the explicit mapping operations.
// http.Response.make(status_code=200, content=b"", headers={}) returns a mutable
// response assignable to flow.response. Request and response http_version is a
// string; scripts compare values such as "HTTP/1.0" or "HTTP/2.0", not boolean
// version aliases. Bytes content, text, headers, trailers and stream setters use
// the native HTTP model's semantics; None preserves missing versus empty data.
// Request bindings also include host, port, scheme, method, authority, path,
// url, pretty_host, pretty_url, query and urlencoded_form. Response bindings
// include status_code and reason. Timestamps are read-only.
//
// dns.types contains A, AAAA and TXT; dns.classes.IN and
// dns.response_codes.NOERROR/NXDOMAIN expose the corresponding native constants.
// dns.ResourceRecord is a module, not a generic callable constructor. Its A,
// AAAA and TXT factories take (name, data, ttl=60); addresses are textual strings.
// DEFAULT_TTL is 60. DNS message bindings expose questions, answers, authorities,
// additionals, flags and integer fields; question is a handle only when exactly
// one question exists. succeed(answers) and fail(response_code) construct native
// responses. Record data is packed Bytes; text and address helpers are strings.
//
// # Context capabilities
//
// ctx.log(message) logs at info; debug, info, warn, error and alert methods select
// a level. ctx.options attributes read copied current native option values and
// write through the native update/rollback machinery. Lists returned by option
// reads are frozen. ctx.master.commands.call(name, *args) uses the registered
// native parameter and return types, not command-line string execution.
// ctx.master.shutdown() requests shutdown without waiting.
//
// on_load receives an ephemeral loader with
// add_option(name, type_name, default, help, choices=[]) and
// add_command(name, function, help=""). Type names are bool, int, str,
// optional-int, optional-str and sequence-of-str. Command functions must accept
// zero arguments. The receiving native addon owns command cleanup.
//
// ctx.sleep(seconds) requires a finite nonnegative representable duration and
// waits cancellably. ctx.http_get(url) returns owned read-only status_code,
// frozen headers and Bytes content. The HTTP client accepts HTTP(S), rejects
// userinfo and this master's actual proxy listener dial tuples, ignores proxy
// environment configuration and carries no inherited authentication or cookies.
// It bounds total work to 10 seconds, dial to 3 seconds, headers to 64 KiB,
// body to 1 MiB, redirects to three and admitted operations to 32 per script.
// Without Config.ListenAddrs, HTTP fails closed. Origins on other loopback ports
// remain usable. Ordinary blocking calls release dispatch only when permitted;
// nested synchronous calls stay inline, while worker calls wait independently.
//
// # Model ownership and concurrent hooks
//
// Mutable flow, request, response, headers, connection, error, message and DNS
// handles expose explicit attributes only, never arbitrary Go fields or sockets.
// Ordinary handles retained in module state are reusable only inside a later
// protected ordinary invocation of that same loaded instance. Ephemeral loader
// and invocation handles expire; retired instances and worker access to ordinary
// handles are rejected. Conversion graphs are bounded to depth 64 and 65,536
// container entries with cycle rejection.
//
// Spell a concurrent flow hook as request = concurrent(_request). Binding
// names, including child-module members, determine eligibility; helper names
// and every non-flow hook are rejected. Calling the wrapper directly is an
// error. A script with a concurrent binding is initialized twice: ordinary
// hooks retain mutable first-instance globals, while workers use an independently
// initialized frozen instance. Top-level effects therefore happen twice. The
// capability graph's no-op Freeze does not freeze shared options or log services.
//
// Each invocation has its own thread and detached flow, preserving source ID and
// Live only on that invocation copy. Connections are read-only snapshots.
// Capacity is min(32, GOMAXPROCS+4) per loaded instance; waiting callers release
// dispatch before admission and cloning. This is not a process-wide heap bound
// across unlimited trusted scripts or reloads. Worker services enter fresh
// dispatch; option reads use the native copying locked getters and can observe
// a transient value that a later rollback restores.
//
// Merge applies changed semantic fields without overwriting untouched live
// edits. Message prefixes retain original indices; worker appends follow any
// live suffix. Structural prefix deletion or reordering is not exposed.
// backup, revert, intercept, resume and kill are checkpointed and replayed in
// order through the public native methods. A protected killed result preserves
// error/Live and is resumed after later actions and at completion, so a later
// revert or intercept cannot strand it. Naturally non-live flows are not treated
// as killed. Revert otherwise retains its public whole-state behavior.
//
// Commands receive a separate mutable argument graph with related flow and list
// references preserved. Immediate flow mutations are copied back as detached
// state; later queue or worker mutations do not cross this boundary. For
// example, replay.client may retain its command-owned flow without sharing a
// worker's subsequent request edits. Command results are detached under dispatch.
//
// Registered child adapters and their wrapper paths are fixed after loading.
// Later changes to the Starlark addons topology fail dispatch instead of silently
// selecting another frozen handler. Removal still tears down the registered
// identities and owned commands. Retirement never joins under dispatch: admitted
// workers may finish and merge into a still-waiting flow, but cancellation drops
// the merge. Close cancels and joins owned work outside dispatch.
package script
