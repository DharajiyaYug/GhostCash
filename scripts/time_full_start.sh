#!/usr/bin/env bash
# Times the bank server's first start with the full-size parameters
# (256-bit q, 3072-bit p, 2048-bit RSA x3). Uses a throwaway state file.
set -u
cd "$(dirname "$0")/.."
STATE=$(mktemp -u /tmp/ghostcash-full-XXXXXX.json)
LOG=$(mktemp /tmp/ghostcash-full-XXXXXX.log)

start=$(date +%s)
./build/bank_server --port 19300 --state "$STATE" > "$LOG" 2>&1 &
pid=$!
for _ in $(seq 1 150); do
    grep -q listening "$LOG" 2>/dev/null && break
    sleep 2
done
end=$(date +%s)
kill "$pid" 2>/dev/null
echo "full-size first start took $((end - start))s"
cat "$LOG"
rm -f "$STATE" "$LOG"
