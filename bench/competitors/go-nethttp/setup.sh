#!/usr/bin/env bash
# Go module with go.sum: the toolchain verifies every module against it (and sum.golang.org).
. "$(dirname "$0")/../lib.sh"
ensure_go
(cd "$COMP/go-nethttp" && GOFLAGS=-mod=readonly CGO_ENABLED=0 go build -trimpath -o "$OPT/bench-go-nethttp" .)
