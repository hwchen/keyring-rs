## Keyring-rs
[![CI](https://github.com/hwchen/keyring-rs/workflows/ci/badge.svg)](https://github.com/hwchen/keyring-rs/actions?query=workflow%3Aci)
[![Crates.io](https://img.shields.io/crates/v/keyring.svg?style=flat-square)](https://crates.io/crates/keyring)
[![API Documentation on docs.rs](https://docs.rs/keyring/badge.svg)](https://docs.rs/keyring)

A cross-platform library to manage storage and retrieval of passwords (and other credential-like secrets) in the underlying platform secure store, with a fully-developed example that provides a command-line interface.

Published on [crates.io](https://crates.io/crates/keyring)

## Usage

__Currently supports Linux, iOS, macOS, and Windows.__ Please file issues if you have any problems or bugs!

To use this library in your project add the following to your `Cargo.toml` file:

```toml
[dependencies]
keyring = "1"
```

This will give you access to the `keyring` crate in your code. Now you can use  the `Entry::new` function to create a new keyring entry. The `new` function expects a `service` name and an `username` which together identify the entry.

Passwords can be added to an entry using its `set_password` method.  They can then be read back using the `get_password` method, and deleted using the `delete_password` method.  (The persistence of the `Entry` is determined via Rust rules, so deleting the password doesn't delete the entry, but it does delete the underlying platform credential which was used to store the password.)

```rust
extern crate keyring;

use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let service = "my_application";
    let username = "my_name";
    let entry = keyring::Entry::new(&service, &username);

    let password = "topS3cr3tP4$$w0rd";
    entry.set_password(&password)?;

    let password = entry.get_password()?;
    println!("My password is '{}'", password);

    entry.delete_password()?;
    println!("My password has been deleted");

    Ok(())
}
```

## Errors

The `get_password`, `set_password` and `delete_password` functions return a `Result` which, if the operation was unsuccessful, can yield a `keyring::Error` with a platform-independent code that describes the error.

## Examples

The keychain-rs project contains a sample application (`cli`) and a sample library (`ios`).

The application is a command-line interface to the keychain.  This can be a great way to explore how the library is used, and it allows experimentation with the use of different service names, usernames, and targets.  When run in "singly verbose" mode (-v), it outputs the retrieved credentials on each `get` run.  When run in "doubly verbose" mode (-vv), it also outputs any errors returned.  This can be a great way to see which errors result from which conditions on each platform.

The sample library is a full exercise of all the iOS functionality; it's meant to be loaded into an iOS test harness such as the one found in [this project](https://github.com/brotskydotcom/rust-on-ios). While the library can be compiled and linked to on macOS as well, doing so doesn't provide any advantages over using standard Rust tests.

## Dev Notes

* We build using GitHub CI.
* Each tag is built on Ubuntu x64, Win 10 x64, and Mac intel x64.  The `cli` example executable is posted for all platforms with the tag.

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributors
Thanks to the following for helping make this library better, whether through contributing code, discussion, or bug reports!

- @bhkaminski
- @brotskydotcom
- @dario23
- @dten
- @gondolyr
- @jasikpark
- @jonathanmorley
- @jyuch
- @lexxvir
- @MaikKlein
- @Phrohdoh
- @Rukenshia
- @samuela
- @stankec
- @steveatinfincia

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
