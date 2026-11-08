BINARY_NAME := agent-bridge
CMD_PKG     := ./cmd/agent-bridge
BIN_DIR     := bin
DIST_DIR    := dist
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo v0.1.1)
GOFLAGS     := -trimpath
LDFLAGS     := -X main.version=$(VERSION)

RELEASE_ARTIFACTS := \
	$(BINARY_NAME)-darwin-arm64 \
	$(BINARY_NAME)-linux-amd64 \
	$(BINARY_NAME)-linux-arm64 \
	$(BINARY_NAME)-windows-amd64.exe

.PHONY: all build build-all test vet clean

all: vet test build

build:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME) $(CMD_PKG)

build-all:
	@mkdir -p $(DIST_DIR)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)-windows-amd64.exe $(CMD_PKG)
	CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)-linux-amd64 $(CMD_PKG)
	CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)-linux-arm64 $(CMD_PKG)
	CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)-darwin-arm64 $(CMD_PKG)
	@( cd $(DIST_DIR) && \
		if command -v sha256sum >/dev/null 2>&1; then \
			sha256sum $(RELEASE_ARTIFACTS); \
		else \
			shasum -a 256 $(RELEASE_ARTIFACTS); \
		fi \
	) | LC_ALL=C sort -k2 > $(DIST_DIR)/SHA256SUMS.txt

test:
	go test -race -v ./...

vet:
	go vet ./...

clean:
	rm -rf $(BIN_DIR) $(DIST_DIR) coverage.out $(BINARY_NAME) $(BINARY_NAME).exe
