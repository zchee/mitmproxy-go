# Transparent TCP mode

This runbook describes setup and evidence requirements, not completed native
acceptance. Run commands from the repository root. Transparent mode recovers
TCP's original destination after operating-system redirection; it is not an
explicit HTTP proxy and does not intercept UDP. A successful direct curl
response without a recorded proxy flow is not interception evidence.

The transparent listener, platform lookup, parser and manual PF test carrier
are implemented. The Linux commands below require the separately tagged
privileged REDIRECT acceptance carrier; its availability and filled receipts
must be checked before treating the procedure as evidence. SOCKS5 listener
admission is separate and available.

Use a controlled origin and a disposable test topology. Install the test CA in
the client trust configuration for HTTPS; do not use curl `-k`. Keep the origin,
listener and client tuples, installed rules/counters, curl exit status, saved
flows and request/response hook counts. The saved `server_conn.address` must be
the pre-redirection origin, not the proxy listener. `client.sockname` remains
the accepted socket's actual local address.

Sudo is for lookup, rule installation and test privilege, not permission to run
arbitrary commands derived from traffic. Compile binaries as the normal user,
then run only the reviewed prebuilt test under root. Do not run `sudo go test`.

## Linux IPv4 and IPv6 REDIRECT

Install `iproute2`, `iptables` (including `ip6tables`), curl and the toolchain
required by `go.mod`. Both IP families and NAT support are required; missing
IPv6, missing privilege or an unsupported kernel is an acceptance failure, not
a passing skip. Original-destination lookup uses `SO_ORIGINAL_DST` in the
accepted socket's normalized IPv4 or IPv6 family.

For the executable acceptance row, build and inventory before elevation:

```bash
set -euo pipefail
work="$PWD/_test/transparent-linux"
test ! -e "$work"
mkdir -p "$work"
go build -o "$work/mitmdump" ./cmd/mitmdump
go test -tags integration,transparentprivileged -c \
  -o "$work/modeserver-integration.test" ./internal/proxy/modeserver
"$work/modeserver-integration.test" \
  -test.list '^TestTransparentRedirectAcceptance$' \
  | tee "$work/inventory.txt"
diff -u <(printf '%s\n' TestTransparentRedirectAcceptance) "$work/inventory.txt"
date -u '+%Y-%m-%dT%H:%M:%SZ' | tee "$work/start.txt"
timeout --signal=QUIT --kill-after=15s 20m \
  sudo -n /usr/bin/env MITMPROXY_TEST_MITMDUMP="$work/mitmdump" \
  "$work/modeserver-integration.test" \
  -test.run '^TestTransparentRedirectAcceptance$' \
  -test.count=1 -test.timeout=15m -test.v 2>&1 | tee "$work/test.log"
date -u '+%Y-%m-%dT%H:%M:%SZ' | tee "$work/end.txt"
if grep -Eq '^[[:space:]]*--- SKIP:' "$work/test.log"; then
  exit 1
fi
grep -Eq '^--- PASS: TestTransparentRedirectAcceptance ' "$work/test.log"
```

The selected test owns its isolated namespaces, rules, origins, proxy and curl
processes, including teardown on errors. Its separate privileged build tag keeps
this root-only row out of ordinary integration runs without adding a skip.
The hosted Packet modes job retains the existing five packet-source scenarios
and uploads evidence even if the added transparent row fails.

### Rule scope and own-flow exemption

For operator-controlled local traffic, use a fresh namespace and distinct
client/proxy users. The following rules illustrate the required scope, not a
whole-host interception recipe. Before installing them, start controlled HTTP
and HTTPS origins on `127.0.0.2` and `::1`, ports 18080/18443, plus a transparent
listener on port 8080, inside the same namespace. Run only the selected client
as `client_uid`; run mitmdump as a different `proxy_uid`. Neither UID is derived
from a network request.

```bash
: "${namespace:?name of the fresh namespace owned by this test}"
: "${client_uid:?numeric UID of the controlled curl client}"
: "${proxy_uid:?numeric UID of the proxy process}"
test "$client_uid" != "$proxy_uid"
sudo ip -n "$namespace" link set lo up
sudo ip netns exec "$namespace" iptables-save | grep -v '^#' >| "$work/ipv4-before.txt"
sudo ip netns exec "$namespace" ip6tables-save | grep -v '^#' >| "$work/ipv6-before.txt"
sudo ip netns exec "$namespace" iptables -t nat -A OUTPUT \
  -p tcp -m owner --uid-owner "$proxy_uid" -j RETURN
sudo ip netns exec "$namespace" ip6tables -t nat -A OUTPUT \
  -p tcp -m owner --uid-owner "$proxy_uid" -j RETURN
sudo ip netns exec "$namespace" iptables -t nat -A OUTPUT \
  -p tcp -d 127.0.0.2 -m multiport --dports 18080,18443 \
  -m owner --uid-owner "$client_uid" -j REDIRECT --to-ports 8080
sudo ip netns exec "$namespace" ip6tables -t nat -A OUTPUT \
  -p tcp -d ::1 -m multiport --dports 18080,18443 \
  -m owner --uid-owner "$client_uid" -j REDIRECT --to-ports 8080
sudo ip netns exec "$namespace" iptables -t nat -L OUTPUT -nvx \
  >| "$work/ipv4-counters.txt"
sudo ip netns exec "$namespace" ip6tables -t nat -L OUTPUT -nvx \
  >| "$work/ipv6-counters.txt"
```

A client-owner rule without a distinct proxy identity can redirect mitmdump's
origin connection back into itself. Do not install unscoped host OUTPUT rules,
flush host NAT tables, or change global forwarding/sysctl settings for this
local-namespace example. Forwarded-device topologies need their own reviewed
interface/source/destination-specific rules and snapshot/restore procedure.

For this exact rule set, first stop and join the owned curl, proxy and origin
processes, then remove only these rules in reverse order:

```bash
sudo ip netns exec "$namespace" ip6tables -t nat -D OUTPUT \
  -p tcp -d ::1 -m multiport --dports 18080,18443 \
  -m owner --uid-owner "$client_uid" -j REDIRECT --to-ports 8080
sudo ip netns exec "$namespace" iptables -t nat -D OUTPUT \
  -p tcp -d 127.0.0.2 -m multiport --dports 18080,18443 \
  -m owner --uid-owner "$client_uid" -j REDIRECT --to-ports 8080
sudo ip netns exec "$namespace" ip6tables -t nat -D OUTPUT \
  -p tcp -m owner --uid-owner "$proxy_uid" -j RETURN
sudo ip netns exec "$namespace" iptables -t nat -D OUTPUT \
  -p tcp -m owner --uid-owner "$proxy_uid" -j RETURN
sudo ip netns exec "$namespace" iptables-save | grep -v '^#' >| "$work/ipv4-after.txt"
sudo ip netns exec "$namespace" ip6tables-save | grep -v '^#' >| "$work/ipv6-after.txt"
cmp "$work/ipv4-before.txt" "$work/ipv4-after.txt"
cmp "$work/ipv6-before.txt" "$work/ipv6-after.txt"
test -z "$(sudo ip netns pids "$namespace")"
sudo ip netns del "$namespace"
test ! -e "/run/netns/$namespace"
```

Register equivalent cleanup before the first mutation when automating this
example. A failing partial setup must not execute an unconditional deletion of
rules it never installed. The executable test supplies this ownership and
failure-path handling; the illustrative commands are for a supervised topology.

## macOS and FreeBSD PF

The native path uses generated per-OS `pfioc_natlook` layouts and ioctl
constants, not a guessed common BSD struct. The authoritative
[platform provenance](../../internal/platform/README.md) names the official
[Apple xnu `xnu-12377.1.9` tree][xnu] and
[FreeBSD `release/14.3.0` tree][freebsd]. Original header notices and nine
pinned-file digests live in `internal/platform/testdata/headers/SHA256SUMS`.
`internal/platform/pf_layout_generated.go` records the resulting 84-byte Darwin
and 76-byte FreeBSD layouts, alignment, used offsets and ioctl values.

Regeneration is an offline developer action from the repository root:

```bash
go run ./internal/platform/genlayout \
  ./internal/platform/testdata/headers \
  ./internal/platform/pf_layout_generated.go
```

The generator uses clang extraction from the pinned declarations. No compiler,
header download, cgo or generation runs in the proxy. Darwin/FreeBSD issue the
ioctl through x/sys's raw syscall path; on Darwin arm64 this is raw SVC, not a
libSystem trampoline. First-use tuple validation and bounded text fallback guard
a native refusal. A FreeBSD cross-build proves compilation, not native lookup.

PF setup is an operator action. For the macOS acceptance test, the prepared host
must already expose its standard `rdr-anchor "com.apple/*"` dispatch; the test
refuses to replace the host ruleset. It owns `com.apple/mitmproxy-go-<pid>` and
acquires one PF enable reference with `pfctl -E`, retaining the returned token
for `pfctl -X` cleanup. Do not replace `/etc/pf.conf`, flush shared rules/states,
or globally disable PF used by another service.

The test binds fresh TCP ports for an origin at `127.0.0.2` and a redirected
listener at `127.0.0.1`. Its IPv4 TCP rule is restricted to `lo0`, source
`127.0.0.1`, the exact origin tuple and listener port. A client bound to
`127.0.0.1` sends one byte through the redirected accept before lookup. This
certifies native lookup/self-check, not a full HTTP/HTTPS CLI round-trip.
Other PF topologies need their own reviewed interface/source/origin scope and
proxy-own-flow exemption; an inbound `rdr` rule alone does not redirect traffic
created on that same host.

The resolver opens `/dev/pf` with close-on-exec. On the first usable connection
it compares the ioctl result with `sudo -n /sbin/pfctl -s state` for the exact
same peer. Only an exact matching tuple validates the ioctl path. A mismatch or
layout/ioctl refusal disables that unvalidated path and uses strict PF-state
text lookup. An absent text match is failure, not a passed self-check. After a
validated native path later fails, this and subsequent text-only lookups also
require the PF row's redirected/listener endpoint to equal the accepted local
endpoint as normalized IP/port values. A peer-only or mismatching redirected
row then fails unresolved; initial pre-validation fallback retains upstream's
peer-only lookup. Text capture has a five-second deadline and a 4 MiB combined
stdout/stderr bound; truncation, malformed output and a different peer must not
become a destination. PF-state inspection may expose unrelated connection
metadata: retain its output with appropriate access restrictions.

Grant a named proxy user only the required `/sbin/pfctl -s state` command via an
operator-reviewed sudoers entry if noninteractive fallback is needed. Do not
grant arbitrary `pfctl` arguments or passwordless shells. The preserved privilege
failure is:

> Insufficient privileges to access pfctl. See
> <https://mitmproxy.org/docs/latest/howto-transparent/#macos> for details.

A missing destination reports `Could not resolve original destination.`.

### Parser evidence and mandatory manual root result

Run ordinary parser contracts without root:

```bash
pattern='^(TestOriginalDestinationAddress|TestPFStateLookup|'
pattern+='TestOriginalDestinationFailures|TestOriginalDestinationPFSelfCheck)$'
go test -race -count=1 -v -run "$pattern" ./internal/platform
```

On macOS, build the integration binary as the normal user, inventory it and
record the nonroot portability result separately:

```bash
work="$PWD/_test/transparent-pf"
test ! -e "$work"
mkdir -p "$work"
go test -tags integration -c -o "$work/platform-integration.test" ./internal/platform
"$work/platform-integration.test" -test.list '^TestOriginalDestinationPFIntegration$'
"$work/platform-integration.test" \
  -test.run '^TestOriginalDestinationPFIntegration$' \
  -test.count=1 -test.timeout=10m -test.v
```

A nonroot privilege skip is only portability evidence. Manual root acceptance is
**user-only and not done**; workers must not run these commands. The origin needs
an explicit `127.0.0.2` loopback alias on macOS. Before acceptance, the user adds
it with the absolute `/sbin/ifconfig` path: a GNU inetutils `ifconfig` on PATH
rejects the macOS arguments, including when invoked through sudo.

```bash
sudo /sbin/ifconfig lo0 alias 127.0.0.2 255.255.255.255
sudo /sbin/pfctl -a com.apple -s Anchors | tee "$work/anchors-before.txt"
```

No `com.apple/mitmproxy-go-*` child may appear in the pre-run listing. Stop and
resolve leftovers before proceeding; the top-level `pfctl -s Anchors` listing
does not reveal these nested anchors. After checking the prepared host's anchor
dispatch, the user runs the prebuilt binary manually:

```bash
date -u '+%Y-%m-%dT%H:%M:%SZ' | tee "$work/root-start.txt"
sudo "$work/platform-integration.test" \
  -test.run '^TestOriginalDestinationPFIntegration$' \
  -test.count=1 -test.timeout=10m -test.v 2>&1 | tee "$work/root.log"
date -u '+%Y-%m-%dT%H:%M:%SZ' | tee "$work/root-end.txt"
```

After the test, retain the nested-anchor listing and inspect the exact
`owned_anchor` from its log (replace `<pid>` below with the logged process ID):

```bash
sudo /sbin/pfctl -a com.apple -s Anchors | tee "$work/anchors-after.txt"
sudo /sbin/pfctl -a 'com.apple/mitmproxy-go-<pid>' -sn \
  | tee "$work/owned-anchor-nat-after.txt"
sudo /sbin/ifconfig lo0 -alias 127.0.0.2
```

No `com.apple/mitmproxy-go-*` child may remain in the post-run listing, and the
owned anchor's NAT rules must be empty. Remove the loopback alias after a failed
run too. A receipt without the nested-anchor listing does not prove teardown.

Use the project's serial gate lock and 15-minute outer watchdog for acceptance;
interactive sudo is manual, never unattended password capture. Missing state,
privilege failure or unmatched tuples under the prepared root setup blocks
acceptance. Parser success does not substitute for the native ioctl/self-check.
Require both actual ioctl and exact PF-text tuples to equal the original origin,
with `validated=true` and `disabled=false`. Retain the test's header revision,
layout size/ioctl, peer, accepted local address, both recovered tuples,
validation decision, owned anchor log and `teardown=verified-empty` result.
Cleanup closes all four sockets, flushes only that anchor's NAT and filter
rulesets, verifies both are empty and releases only its PF enable-reference
token. It does not flush global state or disable PF globally; `-F all` and
`-F states` are forbidden because they flush the host's state table even with
an anchor argument.

## Windows and other platforms

The platform availability check refuses transparent mode on Windows with the
exact pinned upstream warning text:

> Transparent mode on Windows is unsupported, flaky, and deprecated.
> Consider using local redirect mode or WireGuard mode instead.

Native Windows CLI/refusal coverage is deferred. The sentence above records the
source contract, not completed native execution; compilation and another OS's
results do not substitute for Windows evidence.

This refusal is a deliberate Go limitation: pinned Python upstream warns but
still has legacy WinDivert code. The port does not acquire WinDivert for
transparent mode. Consider `--mode local:curl` or WireGuard instead; these
alternatives do not imply completed native Windows local-mode acceptance. See
[the Windows local-mode runbook](local-mode-windows.md) for its separate manual
requirements.

OpenBSD's lookup returns the accepted socket's local address, matching the
pinned upstream strategy. No native OpenBSD execution is certified here.
Other unsupported platforms fail explicitly. Neither FreeBSD cross-builds nor
this runbook close the separate macOS/Windows native local-mode requirements.

## Retained results

Fill this table from command outputs and evidence, not expectations. Until a
result is filled and reviewed, it remains unrun or incomplete.

| Result field | Recorded value |
| --- | --- |
| Timestamp from `date`, OS/kernel and toolchain | not run |
| Repository SHA and binary digests | not run |
| Linux IPv4/IPv6 NAT availability, exact rules/counters | not run |
| Origin/listener/client tuples and proxy/client identities | not run |
| HTTP/HTTPS curl exits, test CA, saved flows and hook counts | not run |
| `server_conn.address` is the pre-NAT origin for both families | not run |
| PF header/layout revision, generation and offset checks | not run |
| PF ioctl tuple, text tuple, exact peer and self-check decision | not run |
| Ordinary PF parser / nonroot portability results | not run |
| Manual macOS root ioctl/self-check acceptance | user-only; not done |
| Native Windows Start refusal | deferred; no native certification |
| Process joins, owned rule/anchor/namespace cleanup and restoration | not run |
| Evidence paths, complete logs and SHA-256 manifest | not run |

[xnu]: https://github.com/apple-oss-distributions/xnu/tree/xnu-12377.1.9
[freebsd]: https://github.com/freebsd/freebsd-src/tree/release/14.3.0
