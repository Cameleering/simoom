#!/usr/bin/env bash
. "$(dirname "$0")/../lib.sh"
BIN="$OPT/jdk/bin/java"
VERSION="ls $COMP/vertx/target/lib | grep -m1 vertx-core; $OPT/jdk/bin/java -version 2>&1 | head -1"
CMD=("$OPT/jdk/bin/java" -server -XX:+UseParallelGC -Xms1g -Xmx1g -cp "$COMP/vertx/target/classes:$COMP/vertx/target/lib/*" bench.Main)
dispatch "$@"
