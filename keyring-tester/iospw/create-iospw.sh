#!/bin/bash
set -x
#  cargo-lipo.sh
#  Run cargo lipo to make sure we link the right target
#
#  Created by Daniel Brotsky on 1/1/22.
#  
# The $PATH used by Xcode likely won't contain Cargo, fix that.
# This assumes a default `rustup` setup.
export PATH="$HOME/.cargo/bin:$PATH"

# --xcode-integ determines --release and --targets from Xcode's env vars.
# Depending your setup, specify the rustup toolchain explicitly.
cargo lipo --xcode-integ --manifest-path ../iospw/Cargo.toml
