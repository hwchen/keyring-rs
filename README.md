## Keyring-rs
[![CI](https://github.com/hwchen/keyring-rs/workflows/ci/badge.svg)](https://github.com/hwchen/keyring-rs/actions?query=workflow%3Aci)
[![Crates.io](https://img.shields.io/crates/v/keyring.svg?style=flat-square)](https://crates.io/crates/keyring)
[![API Documentation on docs.rs](https://docs.rs/keyring/badge.svg)](https://docs.rs/keyring)

A cross-platorm library to manage passwords, with a fully-developed example that provides a command-line interface.

Published on [crates.io](https://crates.io/crates/keyring)

## Usage

__Currently supports Linux, macOS, and Windows.__ Please file issues if you have any problems or bugs!

To use this library in your project add the following to your `Cargo.toml` file:

```toml
[dependencies]
keyring = "0.10"
```

This will give you access to the `keyring` crate in your code. Now you can use
the `new` function to create a new `Entry` on the keyring. The `new`
function expects a `service` name and an `username` which together identify
the item.

Passwords can be added to an item using its `set_password` method.  They can then be read back using the `get_password` method, and deleted using the `delete_password` method.  (Note that persistence of the `Entry` is determined via Rust rules, so deleting the password doesn't delete the entry, but it does delete the platform credential.)

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

## Conventions and Caveats

* This module uses platform-native credential managers: secret service on Linux, the Credential Manager on Windows, and the Secure Keychain on Mac.  Each keyring `Entry` (identified by service and username) is mapped to a specific platform credential using conventions described below.
* To facilitate interoperability with third-party software, there are alternate constructors for keyring entries - `Entry::new_with_target` and `Entry::new_with_credential` - that use different conventions to map entries to credentials.  See below and the module documentation for how they work.  In addition, the `get_password_and_credential` method on an entry can be used retrieve the underlying credential information.
* This module manipulates passwords as UTF-8 encoded strings, so if a third party has stored an arbitrary byte string then retrieving that password will return an error.  The error in that case will have the raw bytes attached, so you can access them.

### Linux

* Secret-service groups credentials into collections, and identifies each credential in a collection using a set of key-value pairs (called _attributes_).  In addition, secret-service allows for a label on each credential for use in UI-based clients.
* For a given service/username pair, `Entry::new` maps to a credential in the default (login) secret-service collection.  This credential has matching `service` and `username` attributes, and an additional `application` attribute of `rust-keyring`.
* You can map an entry to non-default secret-service collection by passing the collection's name as the `target` parameter to `Entry::new_with_target`.  This module doesn't ever create collections, so trying to access an entry in a named collection before externally creating and unlocking it will result in a `NoStorageAccess` error.
* If you are running on a headless linux box, you will need to unlock the Gnome login keyring before you can use it.  The following `bash` function may be very helpful.
```shell
function unlock-keyring ()
{
	read -rsp "Password: " pass
	echo -n "$pass" | gnome-keyring-daemon --unlock
	unset pass
}
```
* Trying to access a locked keychain on a headless box often returns the   platform error that displays as `SS error: prompt dismissed`.  This refers to the fact that there is no GUI running that can be used to prompt for a keychain unlock.

### Windows

* There is only one credential store on Windows.  Generic credentials in this store are identified by a single string (called the _target name_).  They also have a number of non-identifying but manipulable attributes: a username, a comment, and a target alias.
* For a given service/username pair, this module uses the concatenated string `username.service` as the mapped credential's target name. (This allows multiple users to store passwords for the same service.)  It also fills the usrename and comment fields with appropriate strings.
* Because the Windows credential manager doesn't support multiple keychains, and because many Windows programs use _only_ the service name as the credential target name, the `Entry::new_with_target` call uses the target parameter as the credential's target name rather than concatenating the username and service.  So if you have a custom algorithm you want to use for computing the Windows target name (such as just the service name), you can specify the target name directly (along with the usual service and username values).

### MacOS

* MacOS credential stores are called keychains, and the OS automatically creates three of them (or four if removable media is being used).  Generic credentials on Mac can be identified by a large number of _key/value_ attributes; this module (currently) uses only the _account_ and _name_ attributes.
* For a given service/username pair, this module uses a generic credential in the User (login) keychain whose _account_ is the username and and whose _name_ is the service.  In the _Keychain Access_ UI, generic credentials created by this module show up in the passwords area (with their _where_ field equal to their _name_), but _Note_ entries on Mac are also generic credentials and can be accessed by this module if you know their _account_ value (which is not displayed by _Keychain Access_).
* You can specify targeting a different keychain by passing the keychain's (case-insensitive) name as the target parameter to `Entry::new_with_target`. Any name other than one of the OS-supplied keychains (User, Common, System, and Dynamic) will be mapped to `User`.  (_N.B._ The latest versions of the MacOS SDK no longer support creation of file-based keychains, so this module's experimental support for those has been removed.)
* Accessing the same keychain entry from multiple threads simultaneously is generally a bad idea, and can cause deadlocks.  This is because MacOS serializes all access and does so in unpredicatable ways.  There is no issue with accessing different entries from multiple threads.

## Sample Application

The keychain-rs project contains a sample application: a command-line interface to the keychain in `cli.rs` in the examples directory.  This can be a great way to explore how the library is used, and it allows experimentation with the use of different service names, user names, and targets.  When run in "singly verbose" mode (-v), it outputs the retrieved credentials on each `get` run.  When run in "doubly verbose" mode (-vv), it also outputs any errors returned.  This can be a great way to see which errors result from which conditions on each platform.

## Dev Notes

* We build using GitHub CI.
* Each tag is built on Ubuntu x64, Win 10 x64, and Mac intel x64.  The `cli` sample executable is posted for all platforms with the tag.

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributors
Thanks to the following for helping make this library better, whether through contributing code, discussion, or bug reports!

- @dario23
- @dten
- @jasikpark
- @jonathanmorley
- @lexxvir
- @Phrohdoh
- @Rukenshia
- @samuela
- @stankec
- @steveatinfincia
- @bhkaminski
- @MaikKlein
- @brotskydotcom

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
