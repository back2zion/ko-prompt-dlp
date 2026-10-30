#!/usr/bin/env bash
# Self-signed certificate for local/dev TLS. Use a CA-issued cert in production.
set -euo pipefail
out="${1:-certs}"; mkdir -p "$out"
openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
  -keyout "$out/key.pem" -out "$out/cert.pem" \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
chmod 600 "$out/key.pem"
echo "wrote $out/cert.pem and $out/key.pem"
echo "run: AXFILTER_REQUIRE_TLS=1 uvicorn main:app --ssl-certfile $out/cert.pem --ssl-keyfile $out/key.pem"
