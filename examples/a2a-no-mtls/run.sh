#!/usr/bin/env bash
# End-to-end no-mTLS agent-to-agent demo across two processes over a real
# socket: a callee `server` fronted by pop.Middleware, and a caller `client`
# that authenticates with a DPoP proof + SCITT receipt/status token — no client
# certificate, no mutual TLS.
#
# Run from the repository root:  ./examples/a2a-no-mtls/run.sh
set -euo pipefail

ADDR="127.0.0.1:18099"
URL="http://${ADDR}/v1/do"
DIR="$(mktemp -d)"
BIN="$(mktemp -d)"
SRV_PID=""

cleanup() {
  [[ -n "${SRV_PID}" ]] && kill "${SRV_PID}" 2>/dev/null || true
  rm -rf "${DIR}" "${BIN}"
}
trap cleanup EXIT

echo "building server + client..."
go build -o "${BIN}/server" ./examples/a2a-no-mtls/server
go build -o "${BIN}/client" ./examples/a2a-no-mtls/client

echo "starting callee (no mTLS)..."
"${BIN}/server" --dir "${DIR}" --addr "${ADDR}" &
SRV_PID=$!

echo
echo "Logs below: component=caller is the calling agent; component=pop is the callee's verifier."
echo
echo "=== 1) authenticated agent-to-agent call (no client certificate) ==="
"${BIN}/client" --dir "${DIR}" --url "${URL}" --mode auth
echo
echo "=== 2) replayed proof (same jti) is rejected ==="
"${BIN}/client" --dir "${DIR}" --url "${URL}" --mode replay
echo
echo "=== 3) request with no identity is rejected ==="
"${BIN}/client" --dir "${DIR}" --url "${URL}" --mode noident
echo
echo "=== 4) OAuth2: a DPoP-bound access token issued to our key is accepted ==="
"${BIN}/client" --dir "${DIR}" --url "${URL}" --mode oauth
echo
echo "=== 5) OAuth2: a token issued to ANOTHER agent's key is refused (cnf.jkt) ==="
"${BIN}/client" --dir "${DIR}" --url "${URL}" --mode stolentoken
echo
echo "PoC complete — authenticated agent-to-agent over a real socket, no mutual TLS."
