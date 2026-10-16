# Original TCP destination lookup

`OriginalAddr(ctx, conn)` never takes ownership of the accepted TCP socket.
`CheckTransparent(ctx)` checks platform support before listener creation; PF
privilege and ABI validation require a real accepted connection. Windows refuses
the deprecated transparent mode with the pinned upstream warning text: unlike this
port, upstream still attempts its legacy WinDivert setup.

Linux selects SOL_IP or SOL_IPV6 after normalizing the accepted local address.
OpenBSD uses the accepted local address. Darwin and FreeBSD use their separately
generated DIOCNATLOOK layouts; neither cross-building nor portable parser tests
prove native execution. An exact same-peer pfctl tuple certifies the native path
on first use. Native refusal or mismatch disables that path for the process and
falls back to bounded text lookup. A missing text tuple is an error, not successful
validation. Commands run outside dispatch with caller cancellation, a five-second
execution deadline and a four-MiB combined stdout/stderr bound.

Darwin/FreeBSD DIOCNATLOOK is a raw syscall through x/sys, without cgo.
There is no exported x/sys libSystem arbitrary-pointer wrapper for this request;
on Darwin arm64 the call reaches Go's raw SVC implementation, not a libSystem
trampoline. The first-use same-peer self-check and bounded text fallback guard
an invalid native path. Native validity is proved only by root ioctl acceptance,
not by successful cross-builds or lint annotations.

## Header provenance and regeneration

Official source revisions:

- Apple xnu `xnu-12377.1.9`:
  https://github.com/apple-oss-distributions/xnu/tree/xnu-12377.1.9
  - `bsd/net/pfvar.h`: `pf_addr`, `pf_state_xport`, `pfioc_natlook`, DIOCNATLOOK.
  - `bsd/sys/ioccom.h`: ioctl encoding macros.
  - `bsd/sys/_types/_sa_family_t.h`: unsigned eight-bit address family.
- FreeBSD `release/14.3.0`:
  https://github.com/freebsd/freebsd-src/tree/release/14.3.0
  - `sys/net/pfvar.h`: `pfioc_natlook`, DIOCNATLOOK.
  - `sys/netpfil/pf/pf.h`: `pf_addr`.
  - `sys/sys/ioccom.h`: ioctl encoding macros.
  - `sys/sys/_types.h` and `sys/sys/socket.h`: unsigned eight-bit address family.

The original headers (including their license notices) are under
`testdata/headers`. Run at the repository root:

```sh
go run ./internal/platform/genlayout ./internal/platform/testdata/headers ./internal/platform/pf_layout_generated.go
```

The generator extracts the actual declarations, removes member alias macros and
uses clang's target-specific record-layout/constant evaluation, not a guessed
shared struct. The fixed-width typedefs match the pinned headers. It emits sizes,
alignment, field offsets and the compiler-evaluated ioctl value. No cgo, compiler,
header download or generation step runs in the proxy. Portable tests assert
Darwin's 84-byte and FreeBSD's 76-byte layouts and all used offsets.

The fixtures `pf01` and `pf02` are copied byte-for-byte from
https://github.com/mitmproxy/mitmproxy/tree/3368a0a06ae6195aad817a1ece1aaeb6fe0353a1/test/mitmproxy/data
(MIT). `pf01` has no terminal newline; a complete terminal state row remains valid,
but incomplete state names, row grammar and endpoint tokens are rejected.

## Manual macOS acceptance

Build as the ordinary user; execute only the test binary as root:

```sh
go test -tags integration -c -o /absolute/evidence/platform-integration.test ./internal/platform
sudo /absolute/evidence/platform-integration.test -test.run '^TestOriginalDestinationPFIntegration$' -test.count=1 -test.timeout=10m -test.v
```

The nonroot run skips only this identity and proves portability, not acceptance.
The prepared host must expose its standard `rdr-anchor "com.apple/*"` dispatch;
the test refuses to replace the host ruleset. It acquires/releases its own PF
enable reference, loads/flushes only its process-named child anchor, uses fresh
loopback origin/listener/client ports, closes all sockets and requires both the
actual ioctl tuple and the exact pfctl tuple to match the pre-redirection origin.
No whole-machine firewall flush or global PF disable is performed. Root permission
failure, absent redirect/state or native mismatch is failure, never a skip.
