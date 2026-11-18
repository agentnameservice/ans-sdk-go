# ans-sdk-go developer targets.
#
# `make build` produces a bin/ans-cli with the known-registries list injected
# the same way a release build does. Plain `go build ./cmd/ans-cli` also works
# and yields a binary with no registry table (every command then needs
# --base-url).

GO ?= go
BIN := bin/ans-cli
PKG := github.com/agentnameservice/ans-sdk-go/cmd/ans-cli/cmd

.PHONY: build build-plain test lint sync-registries clean

build:
	@flags="$$(scripts/fetch-registries.sh)" && \
	  $(GO) build -trimpath -ldflags "$$flags -X $(PKG).version=dev -X $(PKG).commit=$$(git rev-parse --short HEAD)" -o $(BIN) ./cmd/ans-cli && \
	  echo "built $(BIN) with registries from ans-spec $$(tr -d '[:space:]' < cmd/ans-cli/ANS_SPEC_REF)"

build-plain:
	$(GO) build -trimpath -o $(BIN) ./cmd/ans-cli

test:
	$(GO) test -race ./...

lint:
	golangci-lint run ./...

# Move the ans-spec pin to the current tip of main. Review the resulting
# diff in cmd/ans-cli/ANS_SPEC_REF and run `make build` to confirm the list
# still fetches and parses before committing.
sync-registries:
	@sha=$$(git ls-remote https://github.com/agentnameservice/ans-spec refs/heads/main | cut -f1) && \
	  printf '%s\n' "$$sha" > cmd/ans-cli/ANS_SPEC_REF && \
	  echo "pinned ans-spec $$sha"

clean:
	rm -rf bin
