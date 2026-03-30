BINARY_NAME := splunk-installer
VERSION := 1.0.0
BUILD_DIR := build
LDFLAGS := -s -w -X main.BuildVersion=$(VERSION)

.PHONY: all clean linux-amd64 linux-arm64

all: linux-amd64 linux-arm64
	@echo ""
	@echo "Build complete:"
	@ls -lh $(BUILD_DIR)/

linux-amd64:
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build \
		-ldflags "$(LDFLAGS)" \
		-o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 .
	@echo "✓ Built $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64"

linux-arm64:
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build \
		-ldflags "$(LDFLAGS)" \
		-o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 .
	@echo "✓ Built $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64"

clean:
	rm -rf $(BUILD_DIR)
