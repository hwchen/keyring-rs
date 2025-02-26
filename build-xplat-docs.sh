#!/bin/bash

FEATURES="apple-native, windows-native, linux-native-sync-persistent, crypto-rust"
TARGETS=(
    "x86_64-unknown-linux-gnu"
    "aarch64-apple-darwin"
    "aarch64-apple-ios"
    "x86_64-pc-windows-msvc"
)

for TARGET in "${TARGETS[@]}"; do
    cargo +nightly doc --no-deps --features "$FEATURES" --target "$TARGET" -Zbuild-std $OPEN_DOCS
done
