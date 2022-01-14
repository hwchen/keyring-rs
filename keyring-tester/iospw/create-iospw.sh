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
	"armv7")	rust_arch="armv7" ;;
	"arm64")	rust_arch="aarch64" ;;
	"i386")		rust_arch="i386" ;;
	"x86_64")	rust_arch="x86_64" ;;
	*)			echo "error: failed to parse ARCHS: $ARCHS";;
esac
if [[ "$PLATFORM_NAME" == "macosx" ]]; then
	rust_platform="apple-darwin"
else
	rust_platform="apple-ios"
fi
if [[ "$PLATFORM_NAME" == "iphonesimulator" ]]; then
	rust_abi="-sim"
else
	rust_abi=""
fi
rust_target="${rust_arch}-${rust_platform}${rust_abi}"

# Build library in debug or release
if [[ "$CONFIGURATION" == "Release" || "$CONFIGURATION" == "Archive" ]]; then
	rust_config="release"
	cargo build --release --manifest-path ../iospw/Cargo.toml --target ${rust_target}
else
	rust_config="debug"
	cargo build --manifest-path ../iospw/Cargo.toml --target ${rust_target}
fi

# Copy the built library to the derived files directory
cp -v ../target/${rust_target}/${rust_config}/libiospw.a ${DERIVED_FILES_DIR}
