#!/bin/bash
#
# Build libyang as prebuilt library to avoid toolchain compatibility issues
# This script builds libyang with a modern compiler and creates prebuilt binaries
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LIBYANG_DIR="$PROJECT_ROOT/release/src/router/libyang"

# Detect architecture from argument or environment
ARCH="${1:-arm-linux}"
PREBUILT_DIR="$LIBYANG_DIR/prebuilt/$ARCH"

echo "========================================="
echo "Building libyang prebuilt for: $ARCH"
echo "========================================="

# Check if libyang directory exists
if [ ! -d "$LIBYANG_DIR" ]; then
    echo "Error: libyang directory not found at $LIBYANG_DIR"
    exit 1
fi

cd "$LIBYANG_DIR"

# Clean previous builds
rm -rf build-prebuilt
mkdir -p build-prebuilt
mkdir -p "$PREBUILT_DIR/include"

echo "Configuring libyang..."

# Option 1: Native build (if running on target architecture)
# Option 2: Cross-compile with modern toolchain
# Option 3: Use Docker with modern toolchain

# Detect if we should cross-compile or build natively
if [ "$ARCH" = "native" ] || [ "$ARCH" = "$(uname -m)" ]; then
    # Native build
    cd build-prebuilt
    cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DENABLE_BUILD_TESTS=OFF \
        -DENABLE_STATIC=FALSE \
        -DBUILD_SHARED_LIBS=TRUE
else
    # Cross-compile - adjust toolchain as needed
    echo "Cross-compiling for $ARCH"
    
    # Try to detect cross-compiler
    if command -v arm-linux-gnueabi-gcc &> /dev/null; then
        CC=arm-linux-gnueabi-gcc
        CXX=arm-linux-gnueabi-g++
    elif command -v arm-linux-gnueabihf-gcc &> /dev/null; then
        CC=arm-linux-gnueabihf-gcc
        CXX=arm-linux-gnueabihf-g++
    else
        echo "Warning: No ARM cross-compiler found, trying native build"
        CC=gcc
        CXX=g++
    fi
    
    cd build-prebuilt
    cmake .. \
        -DCMAKE_C_COMPILER="$CC" \
        -DCMAKE_CXX_COMPILER="$CXX" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DENABLE_BUILD_TESTS=OFF \
        -DENABLE_STATIC=FALSE \
        -DBUILD_SHARED_LIBS=TRUE
fi

echo "Building libyang..."
make -j$(nproc)

echo "Installing to prebuilt directory..."
make DESTDIR="$PREBUILT_DIR/staging" install

# Copy libraries to prebuilt directory
cp -a "$PREBUILT_DIR/staging/usr/lib"/libyang.so* "$PREBUILT_DIR/" 2>/dev/null || true

# Copy headers
cp -a "$PREBUILT_DIR/staging/usr/include"/libyang "$PREBUILT_DIR/include/" 2>/dev/null || true

# Clean staging
rm -rf "$PREBUILT_DIR/staging"

echo "========================================="
echo "Prebuilt libyang created at:"
echo "$PREBUILT_DIR"
echo ""
ls -lh "$PREBUILT_DIR"
echo "========================================="
echo ""
echo "To use prebuilt libyang, ensure PREBUILT_TAIL is set to '$ARCH' in your build"
echo "Or manually copy files to match your target platform directory structure"
