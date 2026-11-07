#!/usr/bin/env bash
# H2O built from source at a pinned commit, as its docs recommend (https://h2o.examp1e.net/install.html).
. "$(dirname "$0")/../lib.sh"
[ -x "$OPT/h2o/bin/h2o" ] && exit 0
apt_install build-essential cmake pkg-config libssl-dev zlib1g-dev libuv1-dev
fetch "https://github.com/h2o/h2o/archive/$H2O_COMMIT.tar.gz" "$OPT/dl/h2o.tgz" sha256 "$H2O_SHA256"
rm -rf "$OPT/h2o-src" && mkdir -p "$OPT/h2o-src" && tar -xzf "$OPT/dl/h2o.tgz" -C "$OPT/h2o-src" --strip-components=1
cmake -S "$OPT/h2o-src" -B "$OPT/h2o-src/build" -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$OPT/h2o" -DWITH_MRUBY=OFF >/dev/null
cmake --build "$OPT/h2o-src/build" -j"$NPROC" --target h2o >/dev/null
mkdir -p "$OPT/h2o/bin" && install -m 0755 "$OPT/h2o-src/build/h2o" "$OPT/h2o/bin/h2o"
ensure_cert
