#!/usr/bin/env bash
rm -f $HOME/.local/share/keyrings/*
echo -n "test" | gnome-keyring-daemon --replace --unlock
cargo test --verbose
