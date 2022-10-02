/*!

# Keyring

This is a cross-platform library that does storage and retrieval of passwords
(and other credential-like secrets) in an underlying platform-specific secure store.
A top-level introduction to the library's usage, as well as a small code sample,
may be found in [the library's entry on crates.io](https://crates.io/crates/keyring).
Currently supported platforms are
Linux,
Windows,
and iOS/MacOS.

## Design

This crate has a very simple, platform-independent model of a keystore:
it's an API that provides persistent storage for any number of credentials.
Each credential is identified by a <service, username> pair of UTF-8 strings.
Each credential can store a single UTF-8 string as its password.
There is no platform-independent notion of a keystore being locked or unlocked.
There is a platform-independent notion of a credential having platform-specific
metadata that can be read (but not written) via this crate's API.

This crate runs on several different platforms, each of which has one
or more actual secure storage implementations.  Each of these
implementations has its own model---generally a much richer one than
this crate's---for what constitutes a secure credential.  It is
these platform-specific implementations that provide persistent storage.

This crate's simple model for credentials is embodied in the `Credential`
trait.  Each secure storage implementation implements this trait.  This
crate then implements a concrete `Entry` class that can read and write
platform-specific concrete objects via their `Credential` implementations.

## Pluggable Platform Stores

Clients of this crate can provide their own platform-specific credential storage implementations.
They do so by providing a concrete object that implements the `Credential` trait.  They can then
construct an `Entry` in that store by passing that object type to the `Entry::new_with_store` call.
Or they can construct the platform credential themselves and construct an `Entry` that wraps it
by using the `Entry::new_with_credential` call.

## Default Platform Stores

For ease of use, this module provides a default credential storage implementation on each platform:
secure-store on Linux, the Credential Manager on Windows, and Keychain Services on Mac and iOS.
Each entry constructed with `Entry::new(service, username)` is mapped to an underlying credential
using the default store for the platform and conventions described below.

To facilitate interoperability with third-party software that use the default secure stores,
there is an alternate constructor for keyring entries---`Entry::new_with_target`---that
allows clients to influence the mapping from service and username to an underlying
platform credential.  If more control than that is needed, clients can access the underlying
platform store directly and use `Entry::new_with_credential` to wrap the platform credential
in an entry.

### Linux

On Linux, the secret service is used as the platform credential store.  Secret service groups credentials into collections, and identifies each credential in a collection using a set of key-value pairs (called _attributes_).  In addition, secret service allows for a label on each credential for use in UI-based clients.

For a given service/username pair, `Entry::new` maps to a credential in the default (login) secret-service collection.  This credential has matching `service` and `username` attributes, and an additional `application` attribute of `rust-keyring`.

You can map an entry to a non-default secret-service collection by passing the collection's name as the `target` parameter to `Entry::new_with_target`.  This module doesn't ever create collections, so trying to access an entry in a named collection before externally creating and unlocking it will result in a `NoStorageAccess` error.

If you are running on a headless Linux box, you will need to unlock the Gnome login keyring before you can use it.  The following `bash` function may be very helpful.
```shell
function unlock-keyring ()
{
    read -rsp "Password: " pass
    echo -n "$pass" | gnome-keyring-daemon --unlock
    unset pass
}
```

Trying to access a locked keychain on a headless Linux box often returns the  platform error that displays as `SS error: prompt dismissed`.  This refers to the fact that there is no GUI running that can be used to prompt for a keychain unlock.

### Windows

There is only one credential store on Windows.  Generic credentials in this store are identified by a single string (called the _target name_).  They also have a number of non-identifying but manipulable attributes: a username, a comment, and a target alias.

For a given service/username pair, this module uses the concatenated string `username.service` as the mapped credential's target name. (This allows multiple users to store passwords for the same service.)  It also fills the username and comment fields with appropriate strings.

Because the Windows credential manager doesn't support multiple keychains, and because many Windows programs use _only_ the service name as the credential target name, the `Entry::new_with_target` call uses the target parameter as the credential's target name rather than concatenating the username and service.  So if you have a custom algorithm you want to use for computing the Windows target name (such as just the service name), you can specify the target name directly (along with the usual service and username values).

### MacOS and iOS

MacOS/iOS credential stores are called keychains.  On iOS there is only one of these, but on Mac the OS automatically creates three of them (or four if removable media is being used).  Generic credentials on Mac/iOS can be identified by a large number of _key/value_ attributes; this module (currently) uses only the _account_ and _name_ attributes.

For a given service/username pair, this module uses a generic credential in the User (login) keychain whose _account_ is the username and and whose _name_ is the service.  In the _Keychain Access_ UI on Mac, generic credentials created by this module show up in the passwords area (with their _where_ field equal to their _name_), but _Note_ entries on Mac are also generic credentials and can be accessed by this module if you know their _account_ value (which is not displayed by _Keychain Access_).

On Mac, you can specify targeting a different keychain by passing the keychain's (case-insensitive) name as the target parameter to `Entry::new_with_target`. Any name other than one of the OS-supplied keychains (User, Common, System, and Dynamic) will be mapped to `User`.  On iOS, the target parameter is ignored.

(_N.B._ The latest versions of the MacOS SDK no longer support creation of file-based keychains, so this module's experimental support for those has been removed.)

## Caveats

This module manipulates passwords as UTF-8 encoded strings, so if a third party has stored an arbitrary byte string then retrieving that password will return an error.  The error in that case will have the raw bytes attached, so you can access them.

Accessing the same keychain entry from multiple threads simultaneously can produce odd results, even deadlocks.  This is because the system calls to the platform credential managers may use the same thread discipline, and so may be serialized quite differently than the client-side calls.  On MacOS, for example, all calls to access the keychain are serialized in an order that is independent of when they are made.

Because credentials identified with empty service, user, or target names are handled inconsistently at the platform layer, the library had inconsistent (and arguably buggy) behavior in this case.  As of version 1.2, this inconsistency was eliminated by having the library always fail on access when using credentials created with empty strings via `new` or `new_with_target`.  The prior platform-specific behavior can still be accessed by using `new_with_credential` to produce the same credential that would have been produced before the change.

A better way to handle empty strings (and other problematic argument values) would be to allow `Entry` creation to fail gracefully on arguments that are known not to work on a given platform.  That would be a breaking API change, however, so it will have to wait until the next major version.

 */
pub use credential::{Credential, CredentialBuilder};
pub use error::{Error, Result};

pub mod credential;
pub mod error;
pub mod mock;

// Default platform-specific implementations
#[cfg_attr(target_os = "linux", path = "linux.rs")]
#[cfg_attr(target_os = "windows", path = "windows.rs")]
#[cfg_attr(target_os = "macos", path = "macos.rs")]
#[cfg_attr(target_os = "ios", path = "ios.rs")]
pub mod default;

#[derive(Default, Debug)]
struct EntryBuilder {
    inner: Option<Box<CredentialBuilder>>,
}

static mut DEFAULT_BUILDER: EntryBuilder = EntryBuilder { inner: None };

/// Set the credential builder used by default to create entries.
///
/// This sets a mutable static, so it's inherently unsafe.
/// Do not use it to be switching back and forth between builders;
/// set it once before you create any credentials and leave it alone.
/// Use `entry_with_credential` if you are using multiple credential stores
/// and want precise control over which credential is in which store.
pub fn set_default_credential_builder(new: Box<CredentialBuilder>) {
    unsafe {
        DEFAULT_BUILDER.inner = Some(new);
    }
}

fn build_default_credential(target: Option<&str>, service: &str, user: &str) -> Result<Entry> {
    let default = default::default_credential_builder();
    let builder = match unsafe { DEFAULT_BUILDER.inner.as_ref() } {
        None => &default,
        Some(builder) => builder,
    };
    let credential = builder.build(target, service, user)?;
    Ok(Entry { inner: credential })
}

#[derive(Debug)]
pub struct Entry {
    inner: Box<Credential>,
}

impl Entry {
    /// Create an entry for the given service and username.
    /// The default credential builder is used.
    pub fn new(service: &str, user: &str) -> Result<Entry> {
        build_default_credential(None, service, user)
    }

    /// Create an entry for the given target, service, and username.
    /// The default credential builder is used.
    pub fn new_with_target(target: &str, service: &str, user: &str) -> Result<Entry> {
        build_default_credential(Some(target), service, user)
    }

    /// Create an entry that uses the given platform credential for storage.
    pub fn new_with_credential(credential: Box<Credential>) -> Entry {
        Entry { inner: credential }
    }

    /// Set the password for this entry.
    pub fn set_password(&self, password: &str) -> Result<()> {
        self.inner.set_password(password)
    }

    /// Retrieve the password saved for this entry.
    /// Returns a `NoEntry` error is there isn't one.
    pub fn get_password(&self) -> Result<String> {
        self.inner.get_password()
    }

    /// Delete the password for this entry.
    pub fn delete_password(&self) -> Result<()> {
        self.inner.delete_password()
    }

    pub fn get_credential(&self) -> &dyn std::any::Any {
        self.inner.as_any()
    }
}

#[cfg(test)]
mod tests {
    doc_comment::doctest!("../README.md");

    /// When tests fail, they leave keys behind, and those keys
    /// have to be cleaned up before the tests can be run again
    /// in order to avoid bad results.  So it's a lot easier just
    /// to have tests use a random string for key names to avoid
    /// the conflicts, and then do any needed cleanup once everything
    /// is working correctly.  So we export this function for tests to use.
    pub fn generate_random_string_of_len(len: usize) -> String {
        // from the Rust Cookbook:
        // https://rust-lang-nursery.github.io/rust-cookbook/algorithms/randomness.html
        use rand::{distributions::Alphanumeric, thread_rng, Rng};
        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(len)
            .map(char::from)
            .collect()
    }

    pub fn generate_random_string() -> String {
        generate_random_string_of_len(30)
    }
}
