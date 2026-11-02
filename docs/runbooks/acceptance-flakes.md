# Timing-sensitive acceptance cases

These cases remain selected with their original assertions. A successful serial
rerun means **not reproduced serially**, not repaired. Do not exclude a case,
accept a different reset/exit code, relax a deadline, add blind retransmission or
replace a real socket when socket admission/reuse is the property under test.

Retain the original failure and permit one identical serial rerun. A repeated
failure requires separate same-head/main probes; a byte-identical Linux comparison
is deciding only when the local main reproduces the same leaf. Known hosted flakes
permit one failed-job rerun, with the first log retained. A new failure is not
automatically covered merely because it involves a timeout.

## Unrepaired cases

| Package and terminal | Boundary that must remain tested | Why no fixture-only repair is claimed |
|---|---|---|
| `internal/proxy::TestUDPRelayOpenConnectionUpstream/test_ignore_false` | Actual UDP open/forward lifecycle, one server-connect hook and four exact UDP hooks. | An in-memory queue would remove the actual socket path; retransmission can duplicate hooks. |
| `internal/proxy/layers/tlslayer::TestDTLSReverseHandlerTupleReuse/success:_plain_UDP_still_reaches_the_DTLS_origin` | Fixed-tuple close/rebind and plain-UDP to DTLS-origin delivery, including exact payload and hook order. | Resends or queue substitution can change origin attempts and hide an admission/reuse defect. |
| `internal/proxy/modeserver::TestMalformedDNSTupleIsolation` | A malformed datagram must not prevent a valid query on the real listener. | The recorded failure was the valid query's socket-delivery wait, not malformed-message rejection. Retries can create extra flows/disconnects. |
| `internal/proxy/layers/httplayer::TestHTTP3DriverFailureAfterFIN/version_fallback_after_request_FIN` | The exact version-fallback reset code after request FIN. | A request-cancelled code is not equivalent. The fixture already consumes request EOF before cancellation; no deciding fixture-only ordering repair is established. |
| `cmd/mitmdump::TestTransparentCLI/eager_direct_client_fails_closed` | Zero origin requests/flows/body and successful child shutdown. | A listen log can precede completion of startup. Neither a sleep nor a benign dial is a post-startup acknowledgement; accepting exit 1 would weaken the assertion. |
| `script/acceptance::TestScriptAcceptance/contracts/error_once` | Exactly one deliberate hook error, a live response and successful child shutdown. | Listen/running logs precede startup completion. Delaying longer or accepting a startup failure is not a readiness contract. |

The two startup-window cases need either a separately designed post-startup
acknowledgement or proof that an existing acknowledgement suffices. The UDP cases
need real-wire evidence when admission/reuse is the property. The HTTP/3 case
needs diagnosis of the exact reset-code ordering, not a broader accepted-code set.

## Recorded observations

The [DNS capacity fixture change](https://github.com/zchee/mitmproxy-go/pull/281)
uses owned datagram queues for the suppressed-reply UDP retained-limit cases.
All six retained-limit terminals passed 600 repetitions each under the race
profile across one, two and eight Go execution threads. The retained-ID bound,
at-bound reuse, over-limit refusal and finalization assertions are unchanged.
This is a layer-capacity proof, not a repair of the six socket/startup cases above.

The same candidate's hosted Ubuntu proxy integration run observed the transparent
CLI eager-direct-client leaf fail once; one failed-job rerun passed. Local proxy
integration also observed the DTLS tuple-reuse leaf and
`internal/proxy/layers/tlslayer::TestClientTLSRawReplay/wire_cap` fail under
concurrent worker load. Separate serial probes of the candidate and main passed
five repetitions each: **not reproduced serially**, with no repair claim for
those leaves.

Native Windows process/terminal acceptance remains separate. Cross-build success
and a passing host-independent fixture do not establish native driver, socket or
terminal behavior.
