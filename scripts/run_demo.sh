#!/usr/bin/env bash

set -eu
cd "$(dirname "$0")/.."

FAST=""
TLS=1
for arg in "$@"; do
    case "$arg" in
        --fast) FAST="--fast" ;;
        --no-tls) TLS=0 ;;
    esac
done

make servers >/dev/null
mkdir -p demo-data logs

BANK_TLS=()
APP_TLS=()
WALLET_TLS=()
if [ "$TLS" = 1 ]; then
    scripts/make_certs.sh demo-data/tls >/dev/null
    T=demo-data/tls
    BANK_TLS=(--tls-cert "$T/server.crt" --tls-key "$T/server.key")
    APP_TLS=(--tls-cert "$T/server.crt" --tls-key "$T/server.key" --bank-ca "$T/ca.crt")
    WALLET_TLS=(--app-ca "$T/ca.crt")
fi

pids=()
cleanup() {
    echo
    echo "stopping..."
    for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
    wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

./build/bank_server $FAST --state demo-data/bank_state.json "${BANK_TLS[@]}" > logs/bank.log 2>&1 &
pids+=($!)
sleep 3
./build/app_server --users demo-data/users.json "${APP_TLS[@]}" > logs/app.log 2>&1 &
pids+=($!)
sleep 1
./build/wallet_agent --port 8081 --data demo-data/wallet-a "${WALLET_TLS[@]}" > logs/wallet-a.log 2>&1 &
pids+=($!)
./build/wallet_agent --port 8082 --data demo-data/wallet-b "${WALLET_TLS[@]}" > logs/wallet-b.log 2>&1 &
pids+=($!)
sleep 1

echo "GhostCash is running."
if [ "$TLS" = 1 ]; then
    echo "  TLS:      on (wallet -> app -> bank over HTTPS, certificates in demo-data/tls)"
    echo "  third wallet: ./build/wallet_agent --port 8083 --data demo-data/wallet-c --app-ca demo-data/tls/ca.crt"
else
    echo "  TLS:      off"
    echo "  third wallet: ./build/wallet_agent --port 8083 --data demo-data/wallet-c"
fi
echo "  wallet A: http://127.0.0.1:8081/"
echo "  wallet B: http://127.0.0.1:8082/"
echo "  logs:     ./logs/   (bank.log shows double-spend detection)"
echo "Press Ctrl-C to stop."
wait
