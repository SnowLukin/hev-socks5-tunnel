#!/bin/sh
# Session guard smoke: gVisor netstack <-> socketpair <-> hev <-> local SOCKS5 server.
# Needs Go and a static hev build (make static). Usage: tests/session-guard/run.sh [race-iterations]
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
DIR="$ROOT/tests/session-guard"
TMP=$(mktemp -d /tmp/hev-session-guard.XXXXXX)
PORT=31888
LIBS="$ROOT/bin/libhev-socks5-tunnel.a $(find "$ROOT/third-part" -name '*.a' | tr '\n' ' ')"

(cd "$DIR/socksd" && go build -o "$TMP/socksd" .) || exit 1
(cd "$DIR" && CGO_ENABLED=1 CGO_CFLAGS="-I$ROOT/src -I$ROOT/src/core/include" \
    CGO_LDFLAGS="$LIBS" go build -o "$TMP/smoke" .) || exit 1

"$TMP/socksd" -l 127.0.0.1:$PORT >"$TMP/socksd.log" 2>&1 &
SOCKSD=$!
sleep 0.5
"$TMP/smoke" -socks $PORT -log "$TMP/hev.log" -race "${1:-30}"
result=$?
kill $SOCKSD 2>/dev/null
[ $result -eq 0 ] || echo "hev log: $TMP/hev.log"
exit $result
