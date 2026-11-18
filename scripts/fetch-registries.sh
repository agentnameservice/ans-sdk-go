#!/usr/bin/env sh
# Fetch the known-registries list from agentnameservice/ans-spec at the ref
# pinned in cmd/ans-cli/ANS_SPEC_REF, validate it, and print (without a
# trailing newline) the -ldflags fragment that injects it into ans-cli.
#
# Usage:
#   go build -ldflags "$(scripts/fetch-registries.sh)" ./cmd/ans-cli
#
# Env:
#   ANS_SPEC_REF   override the pinned ref (tag, branch, or SHA)
#   ANS_SPEC_BASE  override the raw-content base URL (tests, mirrors)
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ref=${ANS_SPEC_REF:-$(tr -d '[:space:]' < "$here/cmd/ans-cli/ANS_SPEC_REF")}
base=${ANS_SPEC_BASE:-https://raw.githubusercontent.com/agentnameservice/ans-spec}
pkg=github.com/agentnameservice/ans-sdk-go/cmd/ans-cli/internal/registries

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

curl -fsSL --retry 3 -o "$tmp/known-registries.json" "$base/$ref/registries/known-registries.json"
curl -fsSL --retry 3 -o "$tmp/known-registries.schema.json" "$base/$ref/registries/known-registries.schema.json"

if command -v check-jsonschema >/dev/null 2>&1; then
  check-jsonschema --schemafile "$tmp/known-registries.schema.json" "$tmp/known-registries.json" >&2
else
  echo "fetch-registries: check-jsonschema not installed; schema validation skipped (Parse still validates at startup)" >&2
fi

# The Go side re-parses and rejects a malformed document, so a corrupt
# fetch fails the test suite rather than shipping.
encoded=$(base64 < "$tmp/known-registries.json" | tr -d '\n')

printf -- '-X %s.registriesJSON=%s -X %s.specRef=%s' "$pkg" "$encoded" "$pkg" "$ref"
