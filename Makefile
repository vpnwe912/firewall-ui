.PHONY: all build test dev clean install

BUILD_DIR := build
BINARY := $(BUILD_DIR)/firewall-ui
WEB_DIR := web
DIST_DIR := $(WEB_DIR)/dist
GO ?= go
NPM ?= npm

all: build

build:
	@mkdir -p $(BUILD_DIR)
	cd $(WEB_DIR) && $(NPM) run build
	CGO_ENABLED=0 $(GO) build -ldflags="-s -w" -o $(BINARY) ./cmd/firewall-ui
	@cp -r $(DIST_DIR) $(BUILD_DIR)/

test: build
	$(GO) test ./...

dev: build
	$(BINARY) --listen 0.0.0.0:8921

clean:
	rm -rf $(BUILD_DIR) $(DIST_DIR)
	rm -f firewall-ui

install: build
	install -Dm755 $(BINARY) /usr/local/bin/firewall-ui
