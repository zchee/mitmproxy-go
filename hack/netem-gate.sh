#!/usr/bin/env bash
# Sourced by the network gate and its transcript contract tests.

netem_classify() {
  local log="$1" producer="$2" consumer="$3" restoration="$4"
  [[ "${consumer}" == 0 && "${restoration}" == 0 ]] || return 1
  [[ "${producer}" == 0 || "${producer}" == 1 ]] || return 1
  jq -Rse --argjson producer "${producer}" '
    split("\n") as $lines |
    [$lines[] | select(contains("NETEM ")) |
      (capture("^[[:space:]]+[^[:space:]]+_test.go:[0-9]+: NETEM (?<record>.+)$").record // error("malformed marker")) |
      fromjson] as $records |
    [$records[].phase] as $phases |
    $records[-1] as $result |
    def contract:
      .expected_bytes == 268435456 and .window == 16777216 and .stream == 3;
    def positive: type == "number" and . > 0 and . < 1e300;
    def prefix($expected): $phases == $expected;
    def diagnostic:
      test("^[[:space:]]+[^[:space:]]+_test.go:[0-9]+:") | not;
    if (($records | any(.outcome == "protocol-failure")) or
      ($lines | any(test("netem protocol failure|netem peer ended|netem peer context ended|netem upstream owner ended|netem measured wait ended")))) then
      error("measured transfer failed for a protocol reason")
    elif ($lines | any(test("--- SKIP:|panic:|WARNING: DATA RACE"))) then
      error("skip or abnormal test termination")
    elif ($lines | any(select(diagnostic | not) |
      (contains("NETEM ") or test("_test.go:[0-9]+: (tcp_[rw]mem=|qdisc: |netem measured transfer did not complete$|proxy/direct throughput = [0-9.]+, want at least 0.8$)")) | not)) then
      error("unexpected test diagnostic")
    elif $result.phase == "measurement-complete" then
      if (prefix(["setup", "direct-handshake", "direct-warmup", "direct-transfer",
          "direct-complete", "proxy-setup-warmup", "proxy-transfer", "measurement-complete"]) and
        ($records[3] | contract) and ($records[6] | contract) and
        $records[3].leg == "direct" and $records[6].leg == "proxy" and
        ($records[4].duration_ns | positive) and $records[4].bytes == 268435456 and
        ($result | contract) and $result.direct_bytes == 268435456 and
        $result.proxy_bytes == 268435456 and
        $result.direct_duration_ns == $records[4].duration_ns and
        ($result.proxy_duration_ns | positive) and ($result.ratio | positive) and
        (($result.ratio - ($result.direct_duration_ns / $result.proxy_duration_ns)) | fabs) < 0.000000001)
      then
        if $result.ratio >= 0.8 and $result.outcome == "pass" and $producer == 0 and
          ($lines | any(test("^--- PASS: TestHTTP2LoadNetem "))) and
          ($lines | any(test("--- FAIL:")) | not) then
          $result + {classification: "pass"}
        elif $result.ratio < 0.8 and $result.outcome == "below-floor" and $producer == 1 and
          ([$lines[] | select(test("--- FAIL:"))] | length) == 2 and
          ([$lines[] | select(test("_test.go:[0-9]+: proxy/direct throughput ="))] | length) == 1 then
          $result + {classification: "retryable"}
        else error("contradictory measurement result") end
      else error("incomplete or malformed completed measurement") end
    elif $result.phase == "measured-transfer-timeout" then
      if ($producer == 1 and ($result | contract) and
        $result.outcome == "measured-transfer-timeout" and
        $result.last_phase == ($result.leg + "-transfer") and
        $result.actual_bytes == "unavailable" and $result.proxy_bytes == "unavailable" and
        $result.proxy_duration_ns == "unavailable" and $result.ratio == "unavailable" and
        ($result.elapsed_ns | positive) and
        ($result.progress_bytes | type == "number" and . >= 0 and . <= 268435456) and
        ([$lines[] | select(test("--- FAIL:"))] | length) == 2 and
        ([$lines[] | select(endswith("netem measured transfer did not complete"))] | length) == 1 and
        (($result.leg == "direct" and
          prefix(["setup", "direct-handshake", "direct-warmup", "direct-transfer", "measured-transfer-timeout"]) and
          ($records[3] | contract) and $records[3].leg == "direct" and
          $result.direct_duration_ns == "unavailable" and $result.direct_bytes == "unavailable") or
         ($result.leg == "proxy" and
          prefix(["setup", "direct-handshake", "direct-warmup", "direct-transfer", "direct-complete",
            "proxy-setup-warmup", "proxy-transfer", "measured-transfer-timeout"]) and
          ($records[3] | contract) and ($records[6] | contract) and
          $records[3].leg == "direct" and $records[6].leg == "proxy" and
          $records[4].bytes == 268435456 and ($records[4].duration_ns | positive) and
          $result.direct_bytes == 268435456 and
          $result.direct_duration_ns == $records[4].duration_ns))) then
        $result + {classification: "retryable"}
      else error("incomplete or malformed timeout receipt") end
    else error("no classified outcome") end
  ' "${log}"
}

netem_policy() {
  local output="$1" attempt classification
  for attempt in first retry; do
    netem_attempt "${attempt}" || return 1
    classification="$(jq -er '.classification' "${output}/${attempt}/receipt.json")" || return 1
    case "${classification}" in
      pass)
        if [[ "${attempt}" == retry ]]; then
          printf '%s\n' 'accepted flaky measurement under the approved two-attempt policy'
        fi
        return 0
        ;;
      retryable)
        printf 'netem %s: eligible measurement failure; transcript and restoration validated\n' "${attempt}"
        ;;
      *) return 1 ;;
    esac
  done
  return 1
}
