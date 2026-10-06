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
mkdir "$report/.build" "$report/shards"
helper="$report/.build/autobahn"
proxy="$report/.build/mitmdump"
origin_pid=""
proxy_pid=""
suite_pid=""
guard_pid=""
sampler_pid=""
suite_report=""
container_active=0
memory_limit_gib=8

capture_resources() {
  local directory="${suite_report:-$report}"
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
    if [[ $container_active -eq 1 && -s "$directory/container.id" ]]; then
      local container
      container="$(<"$directory/container.id")"
      tail -n 4 "$directory/suite.log" || true
      docker stats --no-stream --format '{{json .}}' "$container" || true
      if [[ "$(uname -s)" = Linux ]]; then
        local field value
        for field in memory.events memory.peak memory.current memory.max memory.swap.max; do
          # Keep the latest readable value if Docker has already dropped the scope.
          if value="$(sudo cat "/sys/fs/cgroup/system.slice/docker-${container}.scope/$field" 2>&1)"; then
            printf '%s\n' "$value" >|"$directory/cgroup-$field.txt"
          fi
          printf '%s: %s\n' "$field" "$value"
        done
      fi
    fi
  } >>"$directory/resource-samples.log" 2>&1
}

finish_suite() {
  [[ -z "$sampler_pid" ]] || kill "$sampler_pid" 2>/dev/null || true
  [[ -z "$sampler_pid" ]] || wait "$sampler_pid" 2>/dev/null || true
  sampler_pid=""
  capture_resources || true
  [[ -z "$guard_pid" ]] || kill "$guard_pid" 2>/dev/null || true
  [[ -z "$guard_pid" ]] || wait "$guard_pid" 2>/dev/null || true
  guard_pid=""
  if [[ -n "$suite_pid" ]]; then
    kill "$suite_pid" 2>/dev/null || true
    local suite_status=0
    wait "$suite_pid" 2>/dev/null || suite_status=$?
    printf '%s\n' "$suite_status" >|"$suite_report/suite-exit-status.txt"
    suite_pid=""
  fi
  if [[ $container_active -eq 1 && -s "$suite_report/container.id" ]]; then
    local container
    container="$(<"$suite_report/container.id")"
    docker inspect --format '{{.State.Status}} oom={{.State.OOMKilled}} exit={{.State.ExitCode}} err={{.State.Error}} finished={{.State.FinishedAt}}' "$container" >|"$suite_report/container-state.txt" 2>&1 || true
    docker inspect --format '{"state":{{json .State}},"memory_limit_bytes":{{.HostConfig.Memory}},"memory_swap_limit_bytes":{{.HostConfig.MemorySwap}}}' "$container" >|"$suite_report/container-state.json" 2>&1 || true
    docker stats --no-stream "$container" >|"$suite_report/container-stats.txt" 2>&1 || true
    docker rm -f "$container" >/dev/null 2>&1 || true
  fi
  container_active=0
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  finish_suite
  if [[ $status -ne 0 ]]; then
    [[ -z "$proxy_pid" ]] || kill -QUIT "$proxy_pid" 2>/dev/null || true
    [[ -z "$origin_pid" ]] || kill -QUIT "$origin_pid" 2>/dev/null || true
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
timeout_seconds="$("$helper" seconds "${WS_GATE_TIMEOUT_SECONDS:-1800}")"
started="$(date +%s)"
# Fresh processes keep the pinned suite's retained results within each family.
groups=("1,2,3,4,5,6,7,8,9,10,11" 12.1 12.2 12.3 12.4 12.5 13.1 13.2 13.3 13.4 13.5 13.6 13.7)
shard_dirs=()
for group in "${groups[@]}"; do
  name="$group"
  [[ "$group" != *,* ]] || name=1-11
  suite_report="$report/shards/$name"
  mkdir "$suite_report"
  shard_dirs+=("$suite_report")
  shard_started="$(date +%s)"
  IFS=',' read -r -a prefixes <<<"$group"
  image="$("$helper" configure "$report/cases.json" "$report/config.template.json" "ws://$container_host:$proxy_port" "$suite_report/fuzzingclient.json" "${prefixes[@]}")"
  remaining=$((timeout_seconds - $(date +%s) + started))
  [[ $remaining -gt 0 ]] || { printf 'Autobahn suite exceeded its aggregate guard\n' >&2; exit 1; }
  date -u '+%Y-%m-%dT%H:%M:%SZ'
  printf 'Autobahn family %s, memory limit %s GiB\n' "$name" "$memory_limit_gib"
  container_active=1
  docker run --env PYTHONUNBUFFERED=1 --memory="${memory_limit_gib}g" --memory-swap="${memory_limit_gib}g" --cidfile "$suite_report/container.id" --network=host --add-host=host.docker.internal:host-gateway -v "$suite_report:/reports" --entrypoint sh "$image" -c '
    wstest -m fuzzingclient -s /reports/fuzzingclient.json
    status=$?
    # Capture exact high-watermarks before Docker destroys the cgroup scope.
    for field in memory.events memory.peak memory.current memory.max memory.swap.max; do
      cat "/sys/fs/cgroup/$field" >|"/reports/cgroup-$field.txt" || true
    done
    exit "$status"
  ' >|"$suite_report/suite.log" 2>&1 &
  suite_pid=$!
  (
    while kill -0 "$suite_pid" 2>/dev/null; do
      capture_resources || true
      sleep 15
    done
  ) &
  sampler_pid=$!
  "$helper" guard "$remaining" "$suite_pid" >|"$suite_report/guard.log" 2>&1 &
  guard_pid=$!
  suite_status=0
  wait "$suite_pid" || suite_status=$?
  printf '%s\n' "$suite_status" >|"$suite_report/suite-exit-status.txt"
  suite_pid=""
  finish_suite
  printf '%s\n' "$(( $(date +%s) - shard_started ))" >|"$suite_report/duration-seconds.txt"
  [[ $suite_status -eq 0 ]] || exit "$suite_status"
  grep -q '^exited oom=false exit=0 err= finished=' "$suite_report/container-state.txt"
  kill -0 "$origin_pid" "$proxy_pid"
done
printf '%s\n' "$(( $(date +%s) - started ))" >|"$report/duration-seconds.txt"
"$helper" verify "$report/cases.json" "$report" "$report/.build/summary.pending.json" "${shard_dirs[@]}"
cleanup
# No success sentinel is published until every case is verified and resources stop.
mv "$report/.build/summary.pending.json" "$report/summary.json"
