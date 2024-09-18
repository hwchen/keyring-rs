#!/bin/bash
cargo doc --no-deps --features=linux-native --target aarch64-unknown-linux-musl $OPEN_DOCS
cargo doc --no-deps --features=windows-native --target aarch64-pc-windows-msvc $OPEN_DOCS
cargo doc --no-deps --features=apple-native --target aarch64-apple-darwin $OPEN_DOCS
cargo doc --no-deps --features=apple-native --target aarch64-apple-ios $OPEN_DOCS
