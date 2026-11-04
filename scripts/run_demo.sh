#!/usr/bin/env bash

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
