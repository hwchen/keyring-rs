#!/bin/bash
set -x
# create-iospw.sh
# Build the correct Rust target and place
# the resultiing library in the build products
#
# The $PATH used by Xcode likely won't contain Cargo, fix that.
# This assumes a default `rustup` setup.
export PATH="$HOME/.cargo/bin:$PATH"

# Figure out the correct Rust target from the ARCHS and PLATFORM.
# This script expects just one element in ARCHS.
case "$ARCHS" in
	"arm64")	rust_arch="aarch64" ;;
	"x86_64")	rust_arch="x86_64" ;;
	*)			echo "error: unsupported architecture: $ARCHS" ;;
esac
if [[ "$PLATFORM_NAME" == "macosx" ]]; then
	rust_platform="apple-darwin"
else
	rust_platform="apple-ios"
fi
if [[ "$PLATFORM_NAME" == "iphonesimulator" ]]; then
    if [[ "${rust_arch}" == "aarch64" ]]; then
        rust_abi="-sim"
    else
        rust_abi=""
    fi
else
	rust_abi=""
fi
rust_target="${rust_arch}-${rust_platform}${rust_abi}"

# Build library in debug or release
if [[ "$CONFIGURATION" == "Release" ]]; then
	rust_config="release"
	cargo build --release --manifest-path ../iospw/Cargo.toml --target ${rust_target}
elif [[ "$CONFIGURATION" == "Debug" ]]; then
	rust_config="debug"
	cargo build --manifest-path ../iospw/Cargo.toml --target ${rust_target}
else
    echo "error: Unexpected build configuration: $CONFIGURATION"
fi

# Copy the built library to the derived files directory
cp -v ../target/${rust_target}/${rust_config}/libiospw.a ${DERIVED_FILES_DIR}
