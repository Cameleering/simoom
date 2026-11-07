#!/usr/bin/env bash
. "$(dirname "$0")/../lib.sh"
rust_build "$COMP/actix" bench-actix
