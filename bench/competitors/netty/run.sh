#!/usr/bin/env bash
. "$(dirname "$0")/../lib.sh"
BIN="$OPT/jdk/bin/java"
VERSION="ls $COMP/netty/target/lib | grep -m1 netty-codec-http; $OPT/jdk/bin/java -version 2>&1 | head -1"
CMD=("$OPT/jdk/bin/java" -server -XX:+UseParallelGC -Xms1g -Xmx1g -cp "$COMP/netty/target/classes:$COMP/netty/target/lib/*" bench.Main)
dispatch "$@"
