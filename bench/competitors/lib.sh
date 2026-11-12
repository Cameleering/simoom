#!/usr/bin/env bash
# Shared helpers for the competitor setup scripts. Sourced, never run. Ubuntu 24.04, as root.
set -euo pipefail
COMP="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=versions.env
. "$COMP/versions.env"
OPT=/opt/bench
mkdir -p "$OPT/dl"
NPROC="$(nproc)"
export PATH="$OPT/go/bin:/root/.cargo/bin:$OPT/node/bin:$OPT/dotnet:$PATH"
export CARGO_TARGET_DIR="$OPT/target-rust"

log() { printf '==> [%s] %s\n' "$(hostname)" "$*" >&2; }

fetch() { # fetch URL FILE ALGO SUM: download once, verify every time
  local url=$1 file=$2 algo=$3 sum=$4
  if [ ! -f "$file" ]; then
    curl -fsSL --proto '=https' --tlsv1.2 -o "$file.part" "$url"
    mv "$file.part" "$file"
  fi
  echo "$sum  $file" | "${algo}sum" -c - >/dev/null || { rm -f "$file"; echo "checksum mismatch: $file" >&2; exit 1; }
}

apt_install() {
  export DEBIAN_FRONTEND=noninteractive
  for _ in $(seq 30); do apt-get install -y -qq "$@" >/dev/null 2>&1 && return 0; sleep 5; apt-get update -qq || true; done
  echo "apt-get install $* failed" >&2; exit 1
}

ensure_rust() {
  if [ ! -x /root/.cargo/bin/cargo ]; then
    fetch "https://static.rust-lang.org/rustup/archive/$RUSTUP_VERSION/x86_64-unknown-linux-gnu/rustup-init" "$OPT/dl/rustup-init" sha256 "$RUSTUP_SHA256"
    chmod +x "$OPT/dl/rustup-init"
    "$OPT/dl/rustup-init" -y -q --profile minimal --default-toolchain "$RUST_TOOLCHAIN" >/dev/null
  fi
  apt_install build-essential pkg-config
}

ensure_go() {
  [ -x "$OPT/go/bin/go" ] && return 0
  fetch "https://go.dev/dl/go$GO_VERSION.linux-amd64.tar.gz" "$OPT/dl/go.tgz" sha256 "$GO_SHA256"
  rm -rf "$OPT/go" && tar -xzf "$OPT/dl/go.tgz" -C "$OPT"
}

ensure_jdk() {
  [ -x "$OPT/jdk/bin/java" ] && [ -x "$OPT/maven/bin/mvn" ] && return 0
  local tag="jdk-${JDK_VERSION/+/%2B}"
  fetch "https://github.com/adoptium/temurin21-binaries/releases/download/$tag/$JDK_FILE" "$OPT/dl/jdk.tgz" sha256 "$JDK_SHA256"
  rm -rf "$OPT/jdk" && mkdir -p "$OPT/jdk" && tar -xzf "$OPT/dl/jdk.tgz" -C "$OPT/jdk" --strip-components=1
  fetch "https://archive.apache.org/dist/maven/maven-3/$MAVEN_VERSION/binaries/apache-maven-$MAVEN_VERSION-bin.tar.gz" "$OPT/dl/maven.tgz" sha512 "$MAVEN_SHA512"
  rm -rf "$OPT/maven" && mkdir -p "$OPT/maven" && tar -xzf "$OPT/dl/maven.tgz" -C "$OPT/maven" --strip-components=1
}

ensure_node() {
  [ -x "$OPT/node/bin/node" ] && return 0
  fetch "https://nodejs.org/dist/v$NODE_VERSION/node-v$NODE_VERSION-linux-x64.tar.xz" "$OPT/dl/node.txz" sha256 "$NODE_SHA256"
  rm -rf "$OPT/node" && mkdir -p "$OPT/node" && tar -xJf "$OPT/dl/node.txz" -C "$OPT/node" --strip-components=1
}

ensure_dotnet() {
  [ -x "$OPT/dotnet/dotnet" ] && return 0
  fetch "https://builds.dotnet.microsoft.com/dotnet/Sdk/$DOTNET_SDK_VERSION/dotnet-sdk-$DOTNET_SDK_VERSION-linux-x64.tar.gz" "$OPT/dl/dotnet.tgz" sha512 "$DOTNET_SHA512"
  rm -rf "$OPT/dotnet" && mkdir -p "$OPT/dotnet" && tar -xzf "$OPT/dl/dotnet.tgz" -C "$OPT/dotnet"
}

# A self-signed P-256 certificate for the TLS listeners (8443).
ensure_cert() {
  [ -f "$OPT/cert/cert.pem" ] && return 0
  mkdir -p "$OPT/cert"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 -subj "/CN=bench.local" \
    -addext "subjectAltName=DNS:bench.local,IP:127.0.0.1" -keyout "$OPT/cert/key.pem" -out "$OPT/cert/cert.pem" 2>/dev/null
}

# Builds a Rust competitor (its own Cargo.lock, crates verified by cargo against it).
rust_build() { # rust_build DIR BIN
  ensure_rust
  (cd "$1" && cargo build -q --release --locked)
  ls -la "$CARGO_TARGET_DIR/release/$2" >&2
}

# run.sh helper: each run.sh sets BIN, VERSION (a command) and CMD (an array), then calls this.
dispatch() {
  case "${1:-}" in
    --print) printf '%q ' "${CMD[@]}"; echo ;;
    --binary) echo "$BIN" ;;
    --version) eval "$VERSION" 2>&1 | head -1 ;;
    *)
      # SIMOOM_TASKSET (bench/cloud/ab.sh variants, any server): run on these CPUs; "notrx" means
      # every CPU that did less than half an even share of the NET_RX softirqs since boot
      local cpus="${SIMOOM_TASKSET:-}"
      if [ "$cpus" = notrx ]; then
        cpus=$(awk '/NET_RX:/ {t = 0; for (i = 2; i <= NF; i++) t += $i; n = NF - 1; o = ""; for (i = 2; i <= NF; i++) if ($i * 2 * n < t) o = o (o == "" ? "" : ",") (i - 2); print o}' /proc/softirqs)
      fi
      if [ -n "$cpus" ]; then exec taskset -c "$cpus" "${CMD[@]}"; fi
      exec "${CMD[@]}" ;;
  esac
}

# The locked version of a crate: lock_version Cargo.lock NAME
lock_version() { awk -v n="$2" '$1=="name" && $3=="\""n"\"" {getline; gsub(/"/,"",$3); print n" "$3; exit}' "$1"; }

# Fixed bodies for S4 (64 KiB and 1 MiB of 'x'), for the servers that serve them from files.
ensure_files() {
  [ -f "$OPT/files/1m" ] && return 0
  mkdir -p "$OPT/files"
  head -c 65536 /dev/zero | tr '\0' x > "$OPT/files/64k"
  head -c 1048576 /dev/zero | tr '\0' x > "$OPT/files/1m"
}
