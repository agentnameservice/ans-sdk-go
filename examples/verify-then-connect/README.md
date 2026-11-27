# Verify, then connect

The README demo. Two ANS agents talk over ordinary HTTPS with **no mutual TLS**,
and each side verifies the other with the artifacts the transparency log already
issues: a **SCITT receipt** (the agent is in the log) and a **status token** (the
agent is ACTIVE and these are its certificates). The caller adds a **DPoP proof**
(it holds the key, for this request).

![demo](demo.gif)

```bash
go run ./examples/verify-then-connect
```

Every line under the narration is the SDK's own log output; nothing is staged.
The demo fails if any scenario does not reach the outcome it narrates, and
`go test ./examples/verify-then-connect` runs it end to end.

## What it shows

| # | Side | Scenario | Result |
|---|------|----------|--------|
| ① | client | *Connect and pray.* A TLS handshake succeeds. That proves the certificate chains to a trusted CA and nothing else. | the gap |
| ② | client | *Verify, then connect.* A preflight `GET /healthz` returns `X-SCITT-Receipt` and `X-ANS-Status-Token`. `ServerVerifier.VerifyWithScitt` checks both signatures against the log key, walks the receipt's inclusion proof, checks status and expiry, and confirms the TLS certificate's fingerprint is in the token's `valid_server_certs`. | verified, tier `FullScitt` |
| ③ | client | *The agent has been revoked.* Its receipt still verifies: the agent was registered. Its status token, signed by the log, says `REVOKED`. | refused: terminal status |
| ④ | client | *The status token has expired.* The receipt verifies and the token's signature is good, but the token ran out ten minutes ago, past the verifier's clock-skew tolerance. An agent the log has stopped vouching for can only replay its last good token. | refused: token expired |
| ⑤ | server | The caller `POST`s with a DPoP proof plus its own receipt and status token. `pop.Middleware` verifies possession, liveness, and identity and binds all three to one identity certificate. | 200 |
| ⑥ | server | The identical proof is sent again. | 401 `REPLAY` |
| ⑦ | server | An attacker with the caller's public headers mints its own key and certificate for the caller's `ans://` name. The proof signature is valid. | 401 `BINDING_FAILED` |
| ⑧ | server | A revoked caller with the right key, right certificate, and a valid proof. | 401 `STATUS_INVALID` |

Slides ③ and ④ are refused before the first real request: the client has sent
nothing but the preflight.

## What is real and what is scaffolding

Real: every verification. The client side is `verify.ServerVerifier.VerifyWithScitt`
with `verify.WithScittKeyLookup`; the server side is `pop.Middleware` with
`pop.WithTrustedHosts`; the caller signs with `pop.AttachIdentity`.

Scaffolding: [`../internal/demokit`](../internal/demokit) stands in for the
Registry Authority and Transparency Log. It mints the identity and server
certificates, maintains a miniature Merkle tree so receipts carry genuine
RFC 9162 inclusion proofs, and signs receipts and status tokens with one log
key. For slide ④ it re-issues one agent's status token with an expiry in the
past. Each agent has its own HTTPS endpoint on a loopback listener; the demo's
HTTP client resolves the agent hostnames to those listeners and trusts their
server certificates, standing in for DNS and a public CA. A real deployment
fetches the artifacts from the Transparency Log and trusts its published root
keys.

## Re-recording the GIF

```bash
brew install asciinema agg
./examples/verify-then-connect/record.sh
```

`record.sh` builds the demo, records it headlessly with `asciinema` at
`--pace 0.45s` into `demo.cast`, and renders `demo.gif` with `agg`. Override
`PACE`, `COLS`, or `ROWS` in the environment to change the timing or frame.
