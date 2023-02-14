#!/bin/bash
cargo doc --no-deps --target x86_64-unknown-linux-musl $OPEN_DOCS
cargo doc --no-deps --target x86_64-pc-windows-gnu $OPEN_DOCS
cargo doc --no-deps --target aarch64-apple-darwin $OPEN_DOCS
cargo doc --no-deps --target aarch64-apple-ios $OPEN_DOCS
