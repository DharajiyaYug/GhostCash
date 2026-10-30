#!/usr/bin/env bash
# Starts a complete GhostCash system on this machine for a manual demo:
#
#   bank server    127.0.0.1:9000
#   app server     127.0.0.1:8000
#   wallet "A"     http://127.0.0.1:8081/
#   wallet "B"     http://127.0.0.1:8082/
#
# Open the two wallet URLs in two browser windows, create two accounts, and
# generate / transfer / redeem coins between them. State lives in ./demo-data
# and survives restarts; delete that folder to start from scratch.
#
# Usage: scripts/run_demo.sh [--fast]     (--fast = small crypto sizes)
# Stop with Ctrl-C.

set -eu
cd "$(dirname "$0")/.."

FAST=""
[ "${1:-}" = "--fast" ] && FAST="--fast"

make servers >/dev/null
mkdir -p demo-data logs

pids=()
cleanup() {
    echo
    echo "stopping..."
    for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
    wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

./build/bank_server $FAST --state demo-data/bank_state.json > logs/bank.log 2>&1 &
pids+=($!)
sleep 3
./build/app_server --users demo-data/users.json > logs/app.log 2>&1 &
pids+=($!)
sleep 1
./build/wallet_agent --port 8081 --data demo-data/wallet-a > logs/wallet-a.log 2>&1 &
pids+=($!)
./build/wallet_agent --port 8082 --data demo-data/wallet-b > logs/wallet-b.log 2>&1 &
pids+=($!)
sleep 1

echo "GhostCash is running."
echo "  wallet A: http://127.0.0.1:8081/"
echo "  wallet B: http://127.0.0.1:8082/"
echo "  logs:     ./logs/   (bank.log shows double-spend detection)"
echo "Press Ctrl-C to stop."
wait
