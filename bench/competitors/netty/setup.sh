#!/usr/bin/env bash
. "$(dirname "$0")/../lib.sh"
ensure_jdk
JAVA_HOME="$OPT/jdk" "$OPT/maven/bin/mvn" -B -q -f "$COMP/netty/pom.xml" package -DskipTests
