# Linux interception configuration apply acknowledgement

This is a proposal for upstream, not an implemented IPC change or a filed
issue. The current Go readiness barrier stays in place until an upstream
release supplies an explicit acknowledgement and its compatibility contract
is verified. No change to `internal/local` is authorized by this document.

## Verified source and ordering

The source was inspected in a detached clone at
`51fe2b7c5aa8439c162abb665db61c6669d146d6`, not inferred from a wheel or
from earlier planning citations.

- [`src/packet_sources/linux.rs:103-111`][frontend-start] waits for the
  redirector's first stdout line and treats it as the IPC endpoint;
  [`:171-191`][frontend-build] then connects the datagram channel and
  publishes the task/configuration sender.
- [`mitmproxy-linux/src/main2.rs:103-110`][endpoint] binds/connects IPC and
  prints the redirector endpoint. eBPF loading happens later, inside the
  spawned task at [`:112-124`][bpf]. Therefore an available endpoint alone
  is not evidence that socket interception has been installed.
- [`main2.rs:142-156`][apply] applies an `InterceptConf` by writing the
  eBPF action array. It sends no applied-configuration reply. Errors in
  individual map writes propagate; oversized action lists are currently
  logged and truncated.
- [`src/ipc/mitmproxy_ipc.proto:10-36`][schema] has `PacketWithMeta`,
  `FromProxy` and `InterceptConf`; there is no sequence identifier or
  configuration-application acknowledgement. The schema is shared with
  Swift, so generated-code and platform compatibility require upstream
  review even for a Linux-only behavioural change.

## Existing Go workaround

[`internal/local/linux.go:234-239,258-283`][go-barrier] serializes writes and
uses a five-second configuration budget. It sends **two byte-identical**
configuration datagrams: the configuration and an identical barrier. It
waits for the Unix-datagram sender queue to drain and reconnects the same
socket to the advertised endpoint to distinguish a live receiver from
queue disposal after peer closure. It sends no third configuration.

The justification is the redirector's serial loop: it applies one
configuration before receiving the next. Startup, send, drain, reconnect,
peer-closure and cancellation failures remain not-ready. This preserves the
current ABI, but readiness depends on transport queue/liveness observations
rather than a message explicitly stating that the configuration was applied.

An acknowledgement would state the condition the frontend actually needs:
all interception actions for this update have been installed successfully
before the frontend admits new client sockets.

## Additive sequence and acknowledgement proposal

The preferred small wire extension is an optional request sequence echoed
in an `InterceptConfApplied` reply. The sequence identifies the update;
receipt of an arbitrary packet or an old update's reply is not readiness.

One additive shape for maintainer review is:

```proto
message InterceptConf {
  repeated string actions = 1;
  optional uint64 sequence = 2;
}

message InterceptConfApplied {
  uint64 sequence = 1;
  bool success = 2;
  string error = 3;
}
```

The reply transport also needs an unambiguous discriminant. Two options:

| Option | Benefit | Constraint |
|---|---|---|
| Add an optional `InterceptConfApplied` field with a new number to the existing redirector-to-proxy datagram schema. | Small additive wire change; normal packet fields stay unchanged. | ACK-only datagrams must have no packet data and must be consumed as control, never injected into the packet engine. |
| Add an explicit redirector-to-proxy envelope with packet and acknowledgement variants. | Cleaner separation of control from packet data. | Requires negotiated opt-in; switching existing packet encoding unconditionally would break old frontends. |

The proposed request field number is unused in the inspected pin, but is
not a committed schema allocation. Maintainers must check schema history
and generated bindings before finalizing it. Do not reuse an existing
field or silently replace the legacy packet format. Upstream should choose
the exact reply container; the required semantics below are independent
of that choice.

### Required semantics

- An absent sequence retains legacy behaviour: no unsolicited ACK is sent.
  Older protobuf decoders can ignore the additive request field; older
  frontends must not receive ACK-only datagrams they might treat as packets.
- A new frontend uses a nonzero, session-scoped update sequence. The reply
  echoes that exact sequence; stale or mismatched replies do not complete
  the current update. The reader remains able to process ordinary packets
  while waiting, without an unbounded queue of ACK waiters.
- Send a success reply only **after** eBPF initialization and every action
  write for that configuration completes. Empty configurations disabling
  interception receive the same apply acknowledgement semantics.
- Validation failures, truncation of a requested action list, or partial
  application must not be reported as full success. An ACK-capable peer
  should send a matching negative result, or terminate on application
  failure; the frontend must preserve that failure and remain not-ready.
- Cancellation and daemon replacement invalidate outstanding waits. An ACK
  does not override a failed write, a closed peer, or an expired budget.
- The ACK promises configuration application, not interception of sockets
  created before the rules became active, process-attribution availability,
  or support for an otherwise unsupported kernel.

## Backward compatibility and Go adoption

A frontend that receives no ACK within its bounded negotiation/barrier
window keeps the existing **two-datagram drain-and-reconnect barrier**. It
must not treat a timeout as successful application on its own. A received
matching negative ACK is an application failure, not permission to fall back
and admit clients. The existing barrier's failure paths remain fail closed.

The existing barrier must remain armed during that bounded ACK attempt;
do not spend the entire budget waiting for an ACK and then start a second
full barrier timeout. Fallback requires the current update's successful
barrier result within the same budget. An ACK-support negotiation policy
must not let a known application failure lose to the fallback.

No extra configuration datagram is added merely to probe for ACK support.
The sequence can be an additive field on the ordinary update. A new peer
must opt into the reply format only for an ACK-requesting frontend, so
old-frontend/new-redirector operation remains unchanged. Existing peers
continue to parse the actions and use the original packet encoding.

After an upstream release carries the protocol, a separate Go change will:

1. Pin and verify the released redirector artifacts and schema; regenerate
   bindings without changing existing field numbers or optional presence.
2. Add a bounded configuration waiter on the owner of the Linux IPC reader,
   keyed by the current update sequence. Control replies must not enter
   the packet engine; addon dispatch must not be held while waiting.
3. Establish readiness from a matching successful ACK, while preserving
   the current barrier for peers that do not acknowledge. Keep the same
   bounded startup/configuration budget and terminal failure behaviour.
4. Verify new/new, new/old and old/new combinations, delayed application,
   negative/stale ACKs, shutdown, cancellation, disabling interception,
   and ordinary packet delivery during a wait. Use real Unix datagrams and
   the native Linux executable gate; synthetic protocol fixtures alone
   cannot prove that eBPF rules were actually applied.

The concrete existing example is the Go serial datagram barrier above:
it addresses this ordering without patching the pinned redirector. The
proposal replaces indirect readiness evidence with an explicit condition;
it does not relax that existing condition or claim a measured speedup.

Design confidence, not runtime measurements: performance 0.90, scalability
0.90, reliability 0.85, cost effectiveness 0.90. The main unverified point
is the exact backward-compatible reply container across generated bindings.

[frontend-start]: https://github.com/mitmproxy/mitmproxy-rs/blob/51fe2b7c5aa8439c162abb665db61c6669d146d6/src/packet_sources/linux.rs#L103-L111
[frontend-build]: https://github.com/mitmproxy/mitmproxy-rs/blob/51fe2b7c5aa8439c162abb665db61c6669d146d6/src/packet_sources/linux.rs#L171-L191
[endpoint]: https://github.com/mitmproxy/mitmproxy-rs/blob/51fe2b7c5aa8439c162abb665db61c6669d146d6/mitmproxy-linux/src/main2.rs#L103-L110
[bpf]: https://github.com/mitmproxy/mitmproxy-rs/blob/51fe2b7c5aa8439c162abb665db61c6669d146d6/mitmproxy-linux/src/main2.rs#L112-L124
[apply]: https://github.com/mitmproxy/mitmproxy-rs/blob/51fe2b7c5aa8439c162abb665db61c6669d146d6/mitmproxy-linux/src/main2.rs#L142-L156
[schema]: https://github.com/mitmproxy/mitmproxy-rs/blob/51fe2b7c5aa8439c162abb665db61c6669d146d6/src/ipc/mitmproxy_ipc.proto#L10-L36
[go-barrier]: https://github.com/zchee/mitmproxy-go/blob/5e841fb/internal/local/linux.go#L234-L283

## Draft upstream issue text

**Title:** Linux redirector: acknowledge applied interception configuration

**Body:**

At `51fe2b7c5aa8439c162abb665db61c6669d146d6`, the Linux redirector prints
its IPC endpoint in `mitmproxy-linux/src/main2.rs:110`, before the spawned
task loads eBPF at `:116`. The frontend accepts that first stdout line in
`src/packet_sources/linux.rs:103-111` and connects the channel at `:171-177`.
The interception-configuration branch at `main2.rs:142-156` updates the
map but sends no applied-configuration response.

Could we add an optional update sequence to `InterceptConf` and an explicit
`InterceptConfApplied` reply echoing the sequence after successful
application? A negative result should distinguish a rejected or partially
applied configuration from success. The reply needs a control/packet
discriminant, and it should be opt-in so old frontends never receive an
ACK-only datagram they could mistake for a packet.

The Go frontend currently sends two identical configuration datagrams,
waits for the sender queue to drain, then reconnects the same socket as a
liveness check before admitting clients. This keeps the existing ABI but
infers application from the redirector's serial receive/apply loop. An
explicit ACK would make the readiness contract observable directly.

For old redirectors, a new frontend can retain that bounded barrier if no
ACK arrives. A matching negative ACK must fail readiness rather than cause
fallback success. The adoption tests should include old/new combinations,
delayed application, negative/stale replies, daemon shutdown/cancellation,
disabling interception and packet delivery while awaiting application.

This is a proposal only; the Go barrier is not removed, and no upstream
issue or patch has been sent by this document.
