# Makefile
.PHONY: all clean ffi ffi-custom install uninstall

# Default target
all: ffi

# Directory configuration
BUILD_DIR = build
SRC_DIR = pkg/attestation

# Installation configuration
PREFIX ?= /usr/local
LIBDIR = $(PREFIX)/lib
INCLUDEDIR = $(PREFIX)/include

# Detect OS for ldconfig
UNAME_S := $(shell uname -s)

# The output shared library
LIB_NAME = libattestation.so
LIB_PATH = $(BUILD_DIR)/$(LIB_NAME)

# Build the FFI shared library
ffi: | $(BUILD_DIR)
	CGO_ENABLED=1 go build -buildmode=c-shared -o $(LIB_PATH) ./cmd/ffi/main.go
	@echo "FFI library built successfully: $(LIB_PATH)"

# Build the FFI shared library with a custom build directory
# Usage: make ffi-custom CUSTOM_BUILD_DIR=path/to/directory
ffi-custom:
	@if [ -z "$(CUSTOM_BUILD_DIR)" ]; then \
		echo "Error: CUSTOM_BUILD_DIR parameter is required"; \
		echo "Usage: make ffi-custom CUSTOM_BUILD_DIR=path/to/directory"; \
		exit 1; \
	fi
	mkdir -p $(CUSTOM_BUILD_DIR)
	CGO_ENABLED=1 go build -buildmode=c-shared -o $(CUSTOM_BUILD_DIR)/$(LIB_NAME) ./cmd/ffi/main.go
	@echo "FFI library built successfully: $(CUSTOM_BUILD_DIR)/$(LIB_NAME)"

# Create build directory if it doesn't exist
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	@echo "Cleaned build artifacts"

# Install the library to system location (may require sudo)
# Usage: make install [PREFIX=/custom/path]
install: ffi
	mkdir -p $(LIBDIR)
	mkdir -p $(INCLUDEDIR)
	install -m 0644 $(LIB_PATH) $(LIBDIR)/
	install -m 0644 $(BUILD_DIR)/$(LIB_NAME:.so=.h) $(INCLUDEDIR)/
	@echo "Library installed to $(LIBDIR)/ and $(INCLUDEDIR)/"

# Uninstall the library from system location (may require sudo)
# Usage: make uninstall [PREFIX=/custom/path]
uninstall:
	rm -f $(LIBDIR)/$(LIB_NAME)
	rm -f $(INCLUDEDIR)/$(LIB_NAME:.so=.h)
	@echo "Library uninstalled from $(LIBDIR)/ and $(INCLUDEDIR)/"