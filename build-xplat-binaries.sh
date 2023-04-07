#!/bin/bash
rustup update
cargo update
cargo clippy --target x86_64-unknown-linux-musl
cargo clippy --target x86_64-pc-windows-gnu
cargo clippy --target aarch64-apple-darwin
cargo clippy --target aarch64-apple-ios
cargo build --target x86_64-unknown-linux-musl
cargo build --target x86_64-pc-windows-gnu
cargo build --target aarch64-apple-darwin
cargo build --target aarch64-apple-ios
