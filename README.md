## Keyring-rs

[![build](https://github.com/hwchen/keyring-rs/actions/workflows/build.yaml/badge.svg)](https://github.com/hwchen/keyring-rs/actions)
[![dependencies](https://deps.rs/repo/github/hwchen/keyring-rs/status.svg)](https://github.com/hwchen/keyring-rs)
[![crates.io](https://img.shields.io/crates/v/keyring.svg?style=flat-square)](https://crates.io/crates/keyring)
[![docs.rs](https://docs.rs/keyring/badge.svg)](https://docs.rs/keyring)

A cross-platform library to manage storage and retrieval of passwords
(and other secrets) in the underlying platform secure store,
with a fully-developed example that provides a command-line interface.

## Usage

To use this library in your project add the following to your `Cargo.toml` file:

```toml
[dependencies]
keyring = "3"
```

This will give you access to the `keyring` crate in your code.
Now you can use the `Entry::new` function to create a new keyring entry.
The `new` function takes a service name
and a user's name which together identify the entry.

Passwords can be added to an entry using its `set_password` method.
They can then be read back using the `get_password` method,
and removed using the `delete_password` method.

```rust
use keyring::{Entry, Result};

fn main() -> Result<()> {
    let entry = Entry::new("my_service", "my_name")?;
    entry.set_password("topS3cr3tP4$$w0rd")?;
    let password = entry.get_password()?;
    println!("My password is '{}'", password);
    entry.delete_password()?;
    Ok(())
}
```

## Errors

Creating and operating on entries can yield a `keyring::Error`
which provides both a platform-independent code
that classifies the error and, where relevant,
underlying platform errors or more information about what went wrong.

## Examples

The keychain-rs project contains a sample application (`cli`)
and a sample library (`ios`).

The `cli` application is a command-line interface to the keyring.
It can be used to explore how the library is used.
It can also be used in debugging keyring-based applications
to probe the contents of the credential store, but you will
want to rebuild it to use the same credential stores
that are used by your application.

The `ios` library is a full exercise of all the iOS functionality;
it's meant to be loaded into an iOS test harness
such as the one found in
[this project](https://github.com/brotskydotcom/rust-on-ios).
While the library can be compiled and linked to on macOS as well,
doing so doesn't provide any advantages over the standard macOS tests.

## Client Testing

This crate comes with a mock credential store
that can be used by clients who want to test
without accessing the native platform store.
The mock store is cross-platform
and allows mocking errors as well as successes.

## Extensibility

This crate allows clients
to "bring their own credential store"
by providing traits that clients can implement.
See the [developer docs](https://docs.rs/keyring/)
for details.

## Platforms

This crate provides built-in implementations of
the following platform-specific credential stores:

* _Linux_: The DBus-based Secret Service and the kernel keyutils.
* _FreeBSD_, _OpenBSD_: The DBus-based Secret Service.
* _macOS_, _iOS_: The local keychain.
* _Windows_: The Windows Credential Manager.

To enable the stores you want, you use features. If you
don't enable any stores for a given platform, the _mock_
keystore will be used. See the [developer docs](https://docs.rs/keyring/) for details.

Please note: Since neither the maintainers nor GitHub do
testing on BSD variants, we rely on contributors
to support these platforms. Thanks for your help!

## Upgrading from v2

The major functional change between v2 and v3 is the addition of
synchronous support for the Secret Service via the
[dbus-secret-service crate](https://crates.io/crates/dbus-secret-service). This means that
keyring users of the Secret Service no longer
need to link with an async runtime.

The only API change between v2 and v3 is that the
default feature set has gone away: you must now specify
explicitly which crate-supported keystores you want included.
So keyring clients will need to update their `Cargo.toml`
file, but not their code.

All v2 data is fully forward-compatible with v3 data;
there have been no changes at all in that respect.

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributors

Thanks to the following for helping make this library better,
whether through contributing code, discussion, or bug reports!

- @Alexei-Barnes
- @benwr
- @bhkaminski
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
- @stankec
- @steveatinfincia
- @Sytten
- @VorpalBlade
- @thewh1teagle

If you should be on this list, but don't find yourself,
please contact @brotskydotcom.

### Contribution

Unless you explicitly state otherwise,
any contribution intentionally submitted
for inclusion in the work by you,
as defined in the Apache-2.0 license,
shall be dual licensed as above,
without any additional terms or conditions.
