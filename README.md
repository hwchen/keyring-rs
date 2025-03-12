## Keyring-rs

[![build](https://github.com/hwchen/keyring-rs/actions/workflows/ci.yaml/badge.svg)](https://github.com/hwchen/keyring-rs/actions)
[![dependencies](https://deps.rs/repo/github/hwchen/keyring-rs/status.svg)](https://deps.rs/repo/github/hwchen/keyring-rs)
[![crates.io](https://img.shields.io/crates/v/keyring.svg?style=flat-square)](https://crates.io/crates/keyring)
[![docs.rs](https://docs.rs/keyring/badge.svg)](https://docs.rs/keyring)

A cross-platform library to manage storage and retrieval of passwords (and other secrets) in the underlying platform secure store, with a fully-developed example that provides a command-line interface.

## Usage

To use this crate in your project, include it in your `Cargo.toml` and don't disable the default features:

```toml
keyring = "4"
```

This will give you access to the `keyring` crate in your code. Now you can use the `Entry::new` function to create a new keyring entry. The `new` function takes a service name and a user's name which together identify the entry.

Passwords (strings) or secrets (binary data) can be added to an entry using its `set_password` or `set_secret` methods, respectively. (These methods create an entry in the underlying platform's persistent credential store.) The password or secret can then be read back using the `get_password` or `get_secret` methods. The underlying credential (with its password/secret data) can then be removed using the `delete_credential` method.

```rust
use keyring::{Entry, Result};

fn main() -> Result<()> {
    let entry = Entry::new("my-service", "my-name")?;
    entry.set_password("topS3cr3tP4$$w0rd")?;
    let password = entry.get_password()?;
    println!("My password is '{}'", password);
    entry.delete_credential()?;
    Ok(())
}
```

## Errors

Creating and operating on entries can yield a `keyring::Error` which provides both a platform-independent code that classifies the error and, where relevant, underlying platform errors or more information about what went wrong.

## Examples

The keychain-rs project contains a sample application (`keyring-cli`) and a sample library (`ios`).

The `keyring-cli` application is a command-line interface to the full functionality of the keyring. Invoke it without arguments to see usage information. It handles binary data input and output using base64 encoding. It can be installed using `cargo install` and used to experiment with library functionality. It can also be used when debugging keyring-based applications to probe the contents of the credential store.

The `ios` library is a full exercise of all the iOS functionality; it's meant to be loaded into an iOS test harness such as the one found in [this project](https://github.com/brotskydotcom/rust-on-ios).

## Client Testing

This crate comes with a mock credential store that can be used by clients who want to test without accessing the native platform store. The mock store is cross-platform and allows mocking errors as well as successes.

## Extensibility

This crate allows clients to "bring their own credential store" by providing traits that clients can implement. See the [developer docs](https://docs.rs/keyring/) for details.

## Platforms

This crate provides built-in implementations of the following platform-specific credential stores:

* _Linux_, _FreeBSD_, _OpenBSD_: The DBus-based Secret Service.
* _macOS_, _iOS_: Keychain Services.
* _Windows_: The Windows Credential Manager.

### Platform-specific issues

Since neither the maintainers nor GitHub do testing on BSD variants, we rely on contributors to support these platforms. Thanks for your help!

If you use the *Secret Service* as your credential store, be aware of the following:

* This implementation requires that `libdbus` be installed on user machines. If you have users whose machines might not have `libdbus` installed, you can specify the `vendored` when building this crate to statically link the dbus library with your app.
* Every call to the Secret Service is done via an inter-process call, which takes time (typically tens if not hundreds of milliseconds).
* By default, this implementation does not encrypt secrets when sending them to or fetching them from the Dbus. If you want them encrypted, you can specify the `encrypted` feature when building this crate.

If you use the *Windows-native credential store*, be careful about multi-threaded access, because the Windows credential store does not guarantee your calls will be serialized in the order they are made.  Always access any single credential from just one thread at a time, and if you are doing operations on multiple credentials that require a particular serialization order, perform all those operations from the same thread.

The *macOS and iOS credential stores* do not allow service names or usernames to be empty, because empty fields are treated as wildcards on lookup.  Use some default, non-empty value instead.

## Upgrading from v3

There are no functional API changes between v4 and v3; all the changes are in the keystores and how they are specified.

Version 4 of this crate removes a number of the built-in credential stores that were available in version 3, namely the async secret service and linux keyutils.

Version 4 of this crate also dispenses with the need to explicitly specify which credential store you want to use on each platform. Instead, the default feature set provides a single credential store on each platform. If you would rather bring your own store, and not build this crate's built-in ones, you can simply suppress the default feature set.

All v2/v3 data is fully forward-compatible with v4 data; there have been no changes at all in that respect.

The Rust edition of this crate has moved to 2024, and the MSRV has moved to 1.85.

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributors

Thanks to the following for helping make this library better, whether through contributing code, discussion, or bug reports!

- @Alexei-Barnes
- @benwr
- @bhkaminski
- @Brooooooklyn
- @brotskydotcom
- @complexspaces
- @connor4312
- @dario23
- @dten
- @gondolyr
- @hwchen
- @jankatins
- @jasikpark
- @jkhsjdhjs
- @jonathanmorley
- @jyuch
- @klemensn
- @landhb
- @lexxvir
- @MaikKlein
- @Phrohdoh
- @phlip9
- @ReactorScram
- @Rukenshia
- @russellbanks
- @ryanavella
- @samuela
- @ShaunSHamilton
- @soywod
- @stankec
- @steveatinfincia
- @Sytten
- @thewh1teagle
- @tmpfs
- @unkcpz
- @VorpalBlade
- @zschreur

If you should be on this list, but don't find yourself, please contact @brotskydotcom.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
