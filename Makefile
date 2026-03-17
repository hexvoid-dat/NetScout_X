.PHONY: all build test lint passive-test generate-passive-fixtures clean

# Makefile, żeby nie klepać wszystkiego z palca za każdym razem. 
# Proste, ale skuteczne.
GO=go
BIN_DIR=./bin

all: build test

build:
	@echo "Building binaries..."
	@mkdir -p $(BIN_DIR)
	$(GO) build -o $(BIN_DIR)/netscoutx ./cmd/net-scout-cli
	$(GO) build -o $(BIN_DIR)/net-scout ./cmd/net-scout

test:
	@echo "Running go tests..."
	$(GO) test ./...

lint:
	@echo "Running go vet..."
	$(GO) vet ./...

passive-test:
	@echo "Running passive engine tests..."
	$(GO) test ./internal/passive -run .

generate-passive-fixtures:
	@echo "Generating passive test fixtures (pcap)..."
	$(GO) run ./internal/passive/testdata/generate

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BIN_DIR)
