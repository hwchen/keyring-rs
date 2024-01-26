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
keyring = "2"
```

This will give you access to the `keyring` crate in your code.
Now you can use  the `Entry::new` function to create a new keyring entry.
The `new` function takes a service name 
and a user name which together identify the entry.

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
to probe the contents of the credential store.

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
See the [developer docs](https://docs.rs/keyring/latest/keyring/) 
for details.

## Platforms

This crate provides secure storage support for
Linux (secret-service and kernel keyutils),
iOS (keychain), macOS (keychain), and
Windows (credential manager).
It also builds on FreeBSD and OpenBSD (secret-service),
and probably works there,
but since neither the maintainers nor GitHub do
testing on BSD variants, we rely on contributors
to support these platforms.  Thanks for your help!

The default features of this crate are set up
to build all the available platform support.
So, for example, if you build on macOS, then
keychain support is enabled by loading
other underlying crates that the keychain
credential store requires.

On Linux, there are two supported platform
credential stores: the secret-service and
the kernel keyutils, and both are built by default.
If you only want to use one or the other, then
you must turn off default features in your
dependency specification and explicitly
specify the feature for the platform support you
want.  For example, you might use
```toml
keyring = { version = "2", default_features = false, features = ["linux-secret-service"] }
```

If you don't build any of the platform support features,
then you will get the `mock` keystore as your default.

PLEASE NOTE: As of version 2.2, turning off the default
feature set will turn off platform support on *all* platforms,
not just on Linux (as was the case before).  While this
behavior is a breaking change on Mac, Windows,
FreeBSD and OpenBSD, the behavior on those platforms before was
unintended and undefined (suppressing default features did nothing),
so this is considered a bug fix rather than
a semver-breaking change that requires a major version bump.

ALSO NOTE: Although the TOML file for this crate specifies a minimum
Rust version of 1.68, that version apples to the library builds _only_.
The TOML has development dependencies that require Rust 1.70.  We
keep each major version of the library compiling on Rust versions 
that are at least as old as the initial release of that major version.

## Upgrading from v1

The v2 release,
although it adds a lot of functionality relative to v1,
is fully compatible with respect to persisted entry data:
it will both read and set passwords on entries that were
originally written by v1, and entries written
by v2 will be readable and updatable by v1.

From a client API point of view, the biggest difference
between v2 and v1 is that entry creation using `Entry::new`
and `Entry::new_with_target` can now fail, so v1 client
code will need to add an `unwrap` or other error handling
in order to work with v2.

There are also new `Error` variants in v2, and the enum
has been declared non-exhaustive (to allow for variants
to be added without breaking client code).
This means that v1 client code that relies on exhaustive
matching will need to be updated.

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
