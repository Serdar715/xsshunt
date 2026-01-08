# XSSHunt Makefile

BINARY_NAME=xsshunt
VERSION=2.0.0
BUILD_DIR=build

.PHONY: all build build-linux build-windows clean install test help

all: build

# Build for current platform
build:
	go build -ldflags="-s -w" -o $(BINARY_NAME) ./cmd/xsshunt

# Build for Linux (amd64)
build-linux:
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/xsshunt
	GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/xsshunt

# Build for Windows
build-windows:
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/xsshunt

# Build for macOS
build-darwin:
	GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/xsshunt
	GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/xsshunt

# Build all platforms
build-all: build-linux build-windows build-darwin

# Install to /usr/local/bin (Linux/macOS)
install: build
	sudo cp $(BINARY_NAME) /usr/local/bin/
	sudo chmod +x /usr/local/bin/$(BINARY_NAME)

# Clean build artifacts
clean:
	rm -f $(BINARY_NAME)
	rm -rf $(BUILD_DIR)

# Run tests
test:
	go test -v ./...

# Download dependencies
deps:
	go mod tidy
	go mod download

# Help
help:
	@echo "XSSHunt - Advanced XSS Scanner"
	@echo ""
	@echo "Usage:"
	@echo "  make build         - Build for current platform"
	@echo "  make build-linux   - Build for Linux (amd64/arm64)"
	@echo "  make build-windows - Build for Windows"
	@echo "  make build-darwin  - Build for macOS"
	@echo "  make build-all     - Build for all platforms"
	@echo "  make install       - Install to /usr/local/bin"
	@echo "  make clean         - Clean build artifacts"
	@echo "  make deps          - Download dependencies"
	@echo "  make test          - Run tests"
