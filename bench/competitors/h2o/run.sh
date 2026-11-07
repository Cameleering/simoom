#!/usr/bin/env bash
. "$(dirname "$0")/../lib.sh"
# a 13-byte static file served from memory after the first read (H2O's fastest fixed-reply path
# without mruby); the index is the body for "/"
mkdir -p "$OPT/h2o-root" && printf 'Hello, World!' > "$OPT/h2o-root/index.html"
BIN="$OPT/h2o/bin/h2o"
VERSION="$OPT/h2o/bin/h2o --version | head -1; echo commit $H2O_COMMIT"
CMD=("$OPT/h2o/bin/h2o" -c "$COMP/h2o/h2o.conf")
dispatch "$@"
