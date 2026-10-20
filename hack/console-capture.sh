#!/usr/bin/env bash
# Capture an owned terminal session from test-controlled actions, without using an existing tmux server.
# Usage: console-capture.sh TMUX OUTPUT ACTIONS COLUMNS ROWS COMMAND [ARG...]
# ACTIONS is tab-separated: unique label, wait|text|key, value (use - for wait), required visible text.
set -euo pipefail

if (( $# < 6 )); then
  printf '%s\n' 'usage: console-capture.sh TMUX OUTPUT ACTIONS COLUMNS ROWS COMMAND [ARG...]' >&2
  exit 2
fi
TMUX_BIN=$1
OUT=$2
ACTIONS=$3
COLUMNS=$4
ROWS=$5
shift 5
case "$OUT" in /*) ;; *) printf '%s\n' 'output path must be absolute' >&2; exit 2 ;; esac
[[ $COLUMNS =~ ^[1-9][0-9]*$ && $ROWS =~ ^[1-9][0-9]*$ ]] || exit 2
test -x "$TMUX_BIN" && test -r "$ACTIONS"
mkdir -p "$OUT"
SOCKET="console-capture-$$"
SESSION=console-capture
printf 'host=%s\nstart=%s\nsize=%sx%s\nsocket_name=%s\nsession=%s\ncommand=' "$(hostname)" "$(date '+%Y-%m-%d %H:%M:%S %Z')" "$COLUMNS" "$ROWS" "$SOCKET" "$SESSION" >| "$OUT/capture.receipt"
printf '%q ' "$@" >> "$OUT/capture.receipt"
printf '\n' >> "$OUT/capture.receipt"
cp "$ACTIONS" "$OUT/actions.tsv"
"$TMUX_BIN" -V >| "$OUT/tmux-version.txt"

finish() {
  local result=$?
  trap - EXIT
  "$TMUX_BIN" -L "$SOCKET" kill-server 2>/dev/null || true
  printf 'end=%s\nexit=%s\n' "$(date '+%Y-%m-%d %H:%M:%S %Z')" "$result" >> "$OUT/capture.receipt"
  exit "$result"
}
trap finish EXIT

printf -v command 'exec %q' "$1"
shift
for argument in "$@"; do
  printf -v quoted ' %q' "$argument"
  command+=$quoted
done
"$TMUX_BIN" -f /dev/null -L "$SOCKET" new-session -d -x "$COLUMNS" -y "$ROWS" -s "$SESSION" "$command"
"$TMUX_BIN" -L "$SOCKET" set-window-option -t "$SESSION:0" remain-on-exit on
"$TMUX_BIN" -L "$SOCKET" display-message -p -t "$SESSION:0.0" 'socket=#{socket_path}; session=#{session_name}; size=#{pane_width}x#{pane_height}; pid=#{pane_pid}' >| "$OUT/pane.txt"
"$TMUX_BIN" -L "$SOCKET" show-option -gv default-terminal >| "$OUT/terminal.txt"

while IFS=$'\t' read -r label operation value expected; do
  [[ $label =~ ^[a-z0-9][a-z0-9-]*$ && -n $expected ]] || { printf '%s\n' 'invalid capture action' >&2; exit 2; }
  test ! -e "$OUT/$label.after.txt" || { printf '%s\n' 'duplicate capture label' >&2; exit 2; }
  "$TMUX_BIN" -L "$SOCKET" capture-pane -p -e -t "$SESSION:0.0" >| "$OUT/$label.before.txt"
  case "$operation" in
    wait) ;;
    text) "$TMUX_BIN" -L "$SOCKET" send-keys -t "$SESSION:0.0" -l -- "$value" ;;
    key) "$TMUX_BIN" -L "$SOCKET" send-keys -t "$SESSION:0.0" -- "$value" ;;
    *) printf '%s\n' 'unknown capture operation' >&2; exit 2 ;;
  esac
  printf '%s\t%s\t%s\t%s\n' "$label" "$operation" "$value" "$(date '+%Y-%m-%d %H:%M:%S %Z')" >> "$OUT/executed-actions.tsv"
  deadline=$(( $(date +%s) + 15 ))
  while :; do
    "$TMUX_BIN" -L "$SOCKET" capture-pane -p -e -t "$SESSION:0.0" >| "$OUT/$label.after.txt"
    if grep -Fq -- "$expected" "$OUT/$label.after.txt"; then
      break
    fi
    if (( $(date +%s) >= deadline )); then
      printf 'capture did not show expected text for %s\n' "$label" >&2
      exit 1
    fi
    sleep 0.05
  done
done < "$ACTIONS"
test -s "$OUT/executed-actions.tsv" || { printf '%s\n' 'capture requires at least one action' >&2; exit 2; }
