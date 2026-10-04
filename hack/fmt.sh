#!/usr/bin/env bash
# Formats every Go file in the module with the project's formatting pipeline.
# A tool that is not installed is skipped with a message, so the script also
# works on a machine that has only the Go toolchain.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

readonly module=github.com/zchee/mitmproxy-go

run() {
	local tool=$1
	shift
	if ! command -v "${tool}" >/dev/null 2>&1; then
		printf 'hack/fmt.sh: %s is not installed; skipping "%s %s"\n' "${tool}" "${tool}" "$*" >&2
		return 0
	fi
	"${tool}" "$@"
}

run gofmt -s -w .
run gofumpt -w -extra .
run modernize -fix -test ./...
run goimports-rereviser -project-name="${module}" -use-cache -cache-fast-skip -rm-unused -set-alias -recursive .
