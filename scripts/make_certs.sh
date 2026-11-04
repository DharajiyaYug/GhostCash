#!/usr/bin/env bash
set -eu

DIR="${1:-demo-data/tls}"
mkdir -p "$DIR"
cd "$DIR"

if [ -f ca.crt ] && [ -f server.crt ] && [ -f server.key ]; then
    echo "TLS certificates already exist in $DIR"
    exit 0
fi

openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 825 \
    -keyout ca.key -out ca.crt -subj "/CN=GhostCash local CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

openssl req -newkey rsa:2048 -nodes -sha256 \
    -keyout server.key -out server.csr -subj "/CN=localhost" 2>/dev/null

cat > server.ext <<EOF
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 825 -sha256 -extfile server.ext 2>/dev/null

rm -f server.csr server.ext ca.srl
chmod 600 ca.key server.key
echo "TLS certificates written to $DIR (ca.crt, server.crt, server.key)"
