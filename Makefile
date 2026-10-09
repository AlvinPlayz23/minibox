.PHONY: build test test-integration bench lint
export PATH := $(HOME)/.local/share/mise/shims:$(PATH)
BIN=bin/minibox
build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BIN) ./cmd/minibox
	@ls -l $(BIN) | awk '{print "binary size:", $$5, "bytes"}'
test:
	go test ./...
test-integration:
	MINIBOX_ROOT=$$(mktemp -d) go test -tags integration ./test/integration/...
bench: build
	bench/run.sh
lint:
	go vet ./...
