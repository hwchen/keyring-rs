#!/bin/bash
echo Rustup and Cargo updates...
rustup install 1.68
rustup +1.68 target add aarch64-unknown-linux-musl
rustup +1.68 target add aarch64-pc-windows-msvc
rustup +1.68 target add aarch64-apple-darwin
rustup +1.68 target add aarch64-apple-ios
rustup update
cargo update
echo Clippy no default features...
cargo clippy --no-default-features --target aarch64-unknown-linux-musl
cargo clippy --no-default-features --target aarch64-pc-windows-msvc
cargo clippy --no-default-features --target aarch64-apple-darwin
cargo clippy --no-default-features --target aarch64-apple-ios
echo Clippy default features...
cargo clippy --target aarch64-unknown-linux-musl
cargo clippy --target aarch64-pc-windows-msvc
cargo clippy --target aarch64-apple-darwin
cargo clippy --target aarch64-apple-ios
echo Compile no default features...
cargo build --no-default-features --target aarch64-unknown-linux-musl
cargo build --no-default-features --target aarch64-pc-windows-msvc
cargo build --no-default-features --target aarch64-apple-darwin
cargo build --no-default-features --target aarch64-apple-ios
echo Compile default features...
cargo build --target aarch64-unknown-linux-musl
cargo build --target aarch64-pc-windows-msvc
cargo build --target aarch64-apple-darwin
cargo build --target aarch64-apple-ios
echo Compile library on 1.68
cargo +1.68 build --target aarch64-unknown-linux-musl --lib
cargo +1.68 build --target aarch64-pc-windows-msvc --lib
cargo +1.68 build --target aarch64-apple-darwin --lib
cargo +1.68 build --target aarch64-apple-ios --lib
