#!/usr/bin/env bash
# Runs the static checks: go vet, then golangci-lint with .golangci.yaml when
# it is installed.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

go vet ./...

if ! command -v golangci-lint >/dev/null 2>&1; then
	echo 'hack/lint.sh: golangci-lint is not installed; skipping "golangci-lint run ./..."' >&2
	exit 0
fi
golangci-lint run --allow-parallel-runners ./...
