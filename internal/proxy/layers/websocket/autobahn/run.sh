#!/usr/bin/env bash
set -euo pipefail

# Keep each run's raw evidence and never reuse an observed report.
if [[ $# -ne 1 ]]; then
  printf 'usage: %s <new-report-directory>\n' "$0" >&2
  exit 2
fi
here="${BASH_SOURCE[0]%/*}"
[[ "$here" = /* ]] || here="$PWD/$here"
report="$1"
[[ "$report" = /* ]] || report="$PWD/$report"
[[ -f "$PWD/go.mod" ]] || {
  printf 'run from the module root\n' >&2; exit 2
}
mkdir "$report"
mkdir "$report/.build"
helper="$report/.build/autobahn"
proxy="$report/.build/mitmdump"
origin_pid=""
proxy_pid=""
suite_pid=""
guard_pid=""
sampler_pid=""

capture_resources() {
  {
    date -u '+%Y-%m-%dT%H:%M:%SZ'
    df -h "$PWD" || true
    du -sh "$report" || true
    if [[ "$(uname -s)" = Linux ]]; then
      free -m || true
      swapon --show || true
      ps -eo pid,rss,comm --sort=-rss | head -n 16 || true
    else
      ps -axo pid,rss,comm | sort -k2 -nr | head -n 16 || true
    fi
    if [[ -s "$report/container.id" ]]; then
      local container
      container="$(<"$report/container.id")"
      tail -n 4 "$report/suite.log" || true
      docker stats --no-stream --format '{{json .}}' "$container" || true
      if [[ "$(uname -s)" = Linux ]]; then
        local field value
        for field in memory.events memory.peak memory.current memory.max memory.swap.max; do
          # Docker can drop the scope on exit; retain the latest readable values.
          if value="$(sudo cat "/sys/fs/cgroup/system.slice/docker-${container}.scope/$field" 2>&1)"; then
            printf '%s\n' "$value" >|"$report/cgroup-$field.txt"
          fi
          printf '%s: %s\n' "$field" "$value"
        done
      fi
    fi
  } >>"$report/resource-samples.log" 2>&1
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  [[ -z "$sampler_pid" ]] || kill "$sampler_pid" 2>/dev/null || true
  [[ -z "$sampler_pid" ]] || wait "$sampler_pid" 2>/dev/null || true
  capture_resources || true
  if [[ $status -ne 0 ]]; then
    [[ -z "$proxy_pid" ]] || kill -QUIT "$proxy_pid" 2>/dev/null || true
    [[ -z "$origin_pid" ]] || kill -QUIT "$origin_pid" 2>/dev/null || true
  fi
  [[ -z "$guard_pid" ]] || kill "$guard_pid" 2>/dev/null || true
  [[ -z "$suite_pid" ]] || kill "$suite_pid" 2>/dev/null || true
  [[ -z "$guard_pid" ]] || wait "$guard_pid" 2>/dev/null || true
  if [[ -n "$suite_pid" ]]; then
    local suite_status=0
    wait "$suite_pid" 2>/dev/null || suite_status=$?
    printf '%s\n' "$suite_status" >|"$report/suite-exit-status.txt"
  fi
  if [[ -f "$report/container.id" ]]; then
    local container
    container="$(<"$report/container.id")"
    docker inspect --format '{{.State.Status}} oom={{.State.OOMKilled}} exit={{.State.ExitCode}} err={{.State.Error}} finished={{.State.FinishedAt}}' "$container" >|"$report/container-state.txt" 2>&1 || true
    docker stats --no-stream "$container" >|"$report/container-stats.txt" 2>&1 || true
    docker rm -f "$container" >/dev/null 2>&1 || true
  fi
  [[ -z "$proxy_pid" ]] || kill "$proxy_pid" 2>/dev/null || true
  [[ -z "$origin_pid" ]] || kill "$origin_pid" 2>/dev/null || true
  [[ -z "$proxy_pid" ]] || wait "$proxy_pid" 2>/dev/null || true
  [[ -z "$origin_pid" ]] || wait "$origin_pid" 2>/dev/null || true
  return "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cp "$here/cases.json" "$report/cases.json"
cp "$here/fuzzingclient.json" "$report/config.template.json"
go build -o "$helper" "$here"
go build -o "$proxy" ./cmd/mitmdump

origin_host="${WS_ORIGIN_HOST:-127.0.0.1}"
origin_port="$("$helper" port "$origin_host" "${WS_ORIGIN_PORT:-9002}")"
proxy_host="${WS_PROXY_HOST:-127.0.0.1}"
proxy_port="$("$helper" port "$proxy_host" "${WS_PROXY_PORT:-9001}")"
origin_bind="$origin_host:$origin_port"
[[ "$origin_host" != *:* ]] || origin_bind="[$origin_host]:$origin_port"
proxy_bind="$proxy_host:$proxy_port"
[[ "$proxy_host" != *:* ]] || proxy_bind="[$proxy_host]:$proxy_port"
"$helper" origin "$origin_bind" "$report/.build/origin.json" >|"$report/origin.log" 2>&1 &
origin_pid=$!
"$helper" wait "$report/.build/origin.json"
origin_address="$("$helper" address "$report/.build/origin.json")"

"$proxy" --mode "reverse:http://$origin_address" --listen-host "$proxy_host" --listen-port "$proxy_port" --set "confdir=$report/.build/confdir" --set block_global=false >|"$report/proxy.log" 2>&1 &
proxy_pid=$!
"$helper" wait "$proxy_bind"
kill -0 "$origin_pid" "$proxy_pid"

container_host="${WS_CONTAINER_HOST:-127.0.0.1}"
if [[ "$(uname -s)" = Darwin && -z "${WS_CONTAINER_HOST:-}" ]]; then
  container_host=host.docker.internal
fi
[[ "$container_host" != *:* ]] || container_host="[$container_host]"
image="$("$helper" configure "$report/cases.json" "$report/config.template.json" "ws://$container_host:$proxy_port" "$report/fuzzingclient.json")"
timeout_seconds="$("$helper" seconds "${WS_GATE_TIMEOUT_SECONDS:-1800}")"
docker run --env PYTHONUNBUFFERED=1 --cidfile "$report/container.id" --network=host --add-host=host.docker.internal:host-gateway -v "$report:/reports" "$image" wstest -m fuzzingclient -s /reports/fuzzingclient.json >|"$report/suite.log" 2>&1 &
suite_pid=$!
(
  while kill -0 "$suite_pid" 2>/dev/null; do
    capture_resources || true
    sleep 15
  done
) &
sampler_pid=$!
"$helper" guard "$timeout_seconds" "$suite_pid" >|"$report/guard.log" 2>&1 &
guard_pid=$!
suite_status=0
wait "$suite_pid" || suite_status=$?
printf '%s\n' "$suite_status" >|"$report/suite-exit-status.txt"
suite_pid=""
[[ $suite_status -eq 0 ]] || exit "$suite_status"
kill "$guard_pid" 2>/dev/null || true
wait "$guard_pid" 2>/dev/null || true
guard_pid=""
kill -0 "$origin_pid" "$proxy_pid"
"$helper" verify "$report/cases.json" "$report" "$report/.build/summary.pending.json"
cleanup
# No success sentinel is published until every case is verified and resources stop.
mv "$report/.build/summary.pending.json" "$report/summary.json"
