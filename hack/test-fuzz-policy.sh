#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

# Accept only the simple trigger mapping; actionlint validates the complete workflow.
check_triggers() {
  awk '
    /^[[:space:]]*($|#)/ { next }
    /^(on|"on"|\047on\047)[[:space:]]*:/ {
      if ($0 !~ /^on:[[:space:]]*$/ || ++blocks != 1) invalid = 1
      triggers = 1
      next
    }
    /^[^[:space:]]/ { triggers = 0 }
    triggers {
      if ($0 ~ /^  workflow_dispatch:[[:space:]]*$/) dispatches++
      else invalid = 1
    }
    END { exit (invalid || blocks != 1 || dispatches != 1) }
  ' "$1"
}

if [[ "${1:-}" = --check ]]; then
  check_triggers "$2"
  exit
fi

ROOT="$(git rev-parse --show-toplevel)"
WORKFLOW="${1:-$ROOT/.github/workflows/fuzz-nightly.yaml}"
WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT

check_triggers "$WORKFLOW"
for mutation in missing quoted double-quoted duplicate schedule push pull_request workflow_run flow scalar; do
  awk -v mutation="$mutation" '
    /^on:$/ {
      if (mutation == "quoted") { print "\047on\047:"; next }
      if (mutation == "double-quoted") { print "\"on\":"; next }
      if (mutation == "duplicate") print "on:\n  workflow_dispatch:"
      if (mutation == "flow") { print "on: [workflow_dispatch, schedule]"; omit = 1; next }
      if (mutation == "scalar") { print "on: schedule"; omit = 1; next }
      print
      if (mutation == "push" || mutation == "pull_request" || mutation == "workflow_run") print "  " mutation ":"
      next
    }
    /^[^[:space:]#]/ { omit = 0 }
    omit { next }
    /^  workflow_dispatch:$/ && mutation == "missing" { next }
    /^  # schedule:$/ && mutation == "schedule" { print "  schedule:"; next }
    /^  #   - cron:/ && mutation == "schedule" { sub(/  #   /, "    "); print; next }
    { print }
  ' "$WORKFLOW" > "$WORK/$mutation.yaml"
  if check_triggers "$WORK/$mutation.yaml"; then
    printf 'invalid fuzz trigger accepted: %s\n' "$mutation" >&2
    exit 1
  fi
done
printf 'PASS manual_dispatch_available\n'
printf 'PASS scheduled_trigger_disabled\n'
