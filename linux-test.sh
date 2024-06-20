#!/usr/bin/env bash
rm -f $HOME/.local/share/keyrings/*
echo -n "test" | gnome-keyring-daemon --unlock
cargo test --verbose
cargo test --features "linux-no-secret-service" --verbose
