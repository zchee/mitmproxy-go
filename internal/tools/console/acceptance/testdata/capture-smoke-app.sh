#!/usr/bin/env bash
set -euo pipefail
printf 'capture-ready\n'
IFS= read -r answer
printf 'received=%s\n' "$answer"
IFS= read -r _finish
