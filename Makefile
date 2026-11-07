BINARY_NAME := agent-bridge
CMD_PKG     := ./cmd/agent-bridge
BIN_DIR     := bin
DIST_DIR    := dist
VERSION     ?= v0.1.0
GOFLAGS     := -trimpath
LDFLAGS     := -s -w -X main.version=$(VERSION)

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

test:
	go test -race -v ./...

vet:
	go vet ./...

clean:
	rm -rf $(BIN_DIR) $(DIST_DIR) coverage.out $(BINARY_NAME) $(BINARY_NAME).exe
