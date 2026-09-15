#!/bin/sh
set -eu

CLI=${DNSID_CLI:-dnsid}
STATE=${DNSID_TESTNET_STATE:-$HOME/.dnsid-testnet}
ZONE=${DNSID_TESTNET_ZONE:-dev.dnsid.test}
BOB_PORT=${BOB_PORT:-3002}
ALICE_PORT=${ALICE_PORT:-3001}
BOB_LOG=${TMPDIR:-/tmp}/dnsid-go-a2a-bob.log
BOB_BIN=${TMPDIR:-/tmp}/dnsid-go-a2a-bob-$$
BOB_PID=

cleanup() {
  if [ -n "$BOB_PID" ]; then
    pkill -TERM -P "$BOB_PID" 2>/dev/null || true
    kill "$BOB_PID" 2>/dev/null || true
    wait "$BOB_PID" 2>/dev/null || true
  fi
  rm -f "$BOB_BIN"
}
trap cleanup EXIT INT TERM

"$CLI" testnet up --state "$STATE"
"$CLI" testnet agent ensure bob --state "$STATE" --upstream "http://localhost:$BOB_PORT" \
  --cu "https://bob.$ZONE/.well-known/agent-card.json" -- \
  "$CLI" log issue --domain "bob.$ZONE"
"$CLI" testnet agent ensure alice --state "$STATE" --upstream "http://localhost:$ALICE_PORT" \
  --cu "https://alice.$ZONE/.well-known/agent-card.json" -- \
  "$CLI" log issue --domain "alice.$ZONE"

go build -o "$BOB_BIN" ./examples/a2a
"$CLI" testnet run bob --state "$STATE" --port "$BOB_PORT" -- "$BOB_BIN" >"$BOB_LOG" 2>&1 &
BOB_PID=$!

for _ in $(seq 1 120); do
  if grep -q "bob.$ZONE ->" "$BOB_LOG"; then
    break
  fi
  if ! kill -0 "$BOB_PID" 2>/dev/null; then
    cat "$BOB_LOG"
    exit 1
  fi
  sleep .25
done

"$CLI" testnet run alice --state "$STATE" --port "$ALICE_PORT" -- go run ./examples/a2a "bob.$ZONE"
printf '\n--- Bob ---\n'
cat "$BOB_LOG"
