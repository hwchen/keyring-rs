/*!

# Keyring

This is a cross-platform library that does storage and retrieval of passwords (and other credential-like secrets) in the underlying platform secure store. A top-level introduction to the library's usage, as well as a small code sample, may be found in [the library's entry on crates.io](https://crates.io/crates/keyring). Currently supported platforms are Linux, Windows, and MacOS.

## Design

This module uses platform-native credential managers: secret service on Linux, the Credential Manager on Windows, and the Secure Keychain on Mac.  Each entry constructed with `Entry::new(service, username)` is mapped to a credential using platform-specific conventions described below.

To facilitate interoperability with third-party software, there are alternate constructors for keyring entries - `Entry::new_with_target` and `Entry::new_with_credential` - that use different conventions to map entries to credentials. In addition, the `get_password_and_credential` method on an entry can be used retrieve the underlying credential data along with the password.

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

### MacOS

MacOS credential stores are called keychains, and the OS automatically creates three of them (or four if removable media is being used).  Generic credentials on Mac can be identified by a large number of _key/value_ attributes; this module (currently) uses only the _account_ and _name_ attributes.

For a given service/username pair, this module uses a generic credential in the User (login) keychain whose _account_ is the username and and whose _name_ is the service.  In the _Keychain Access_ UI, generic credentials created by this module show up in the passwords area (with their _where_ field equal to their _name_), but _Note_ entries on Mac are also generic credentials and can be accessed by this module if you know their _account_ value (which is not displayed by _Keychain Access_).

You can specify targeting a different keychain by passing the keychain's (case-insensitive) name as the target parameter to `Entry::new_with_target`. Any name other than one of the OS-supplied keychains (User, Common, System, and Dynamic) will be mapped to `User`.  (_N.B._ The latest versions of the MacOS SDK no longer support creation of file-based keychains, so this module's experimental support for those has been removed.)

## Caveats

This module manipulates passwords as UTF-8 encoded strings, so if a third party has stored an arbitrary byte string then retrieving that password will return an error.  The error in that case will have the raw bytes attached, so you can access them.

Accessing the same keychain entry from multiple threads simultaneously can produce odd results, even deadlocks.  This is because the system calls to the platform credential managers may use the same thread discipline, and so may be serialized quite differently than the client-side calls.  On MacOS, for example, all calls to access the keychain are serialized in an order that is independent of when they are made.

 */
pub mod credential;
pub mod error;

use credential::{Platform, PlatformCredential};
pub use error::{Error, Result};

/// return the runtime `Platform` so cross-platform
/// code can know what kind of credential is in use.
pub fn platform() -> Platform {
    platform::platform()
}

// Platform-specific implementations
#[cfg_attr(target_os = "linux", path = "linux.rs")]
#[cfg_attr(target_os = "windows", path = "windows.rs")]
#[cfg_attr(target_os = "macos", path = "macos.rs")]
mod platform;

#[derive(Debug)]
pub struct Entry {
    target: PlatformCredential,
}

impl Entry {
    /// Create an entry for the given service and username.
    /// This maps to a target credential in the default keychain.
    pub fn new(service: &str, username: &str) -> Entry {
        Entry {
            target: credential::default_target(&platform(), None, service, username),
        }
    }

    /// Create an entry for the given target, service, and username.
    /// On Linux and Mac, the target is interpreted as naming the collection/keychain
    /// to store the credential.  On Windows, the target is used directly as
    /// the _target name_ of the credential.
    pub fn new_with_target(target: &str, service: &str, username: &str) -> Entry {
        Entry {
            target: credential::default_target(&platform(), Some(target), service, username),
        }
    }

    /// Create an entry that uses the given credential for storage.  Callers can use
    /// their own algorithm to produce a platform-specific credential spec for the
    /// given service and username and then call this entry with that value.
    pub fn new_with_credential(target: &PlatformCredential) -> Result<Entry> {
        if target.matches_platform(&platform()) {
            Ok(Entry {
                target: target.clone(),
            })
        } else {
            Err(Error::WrongCredentialPlatform)
        }
    }

    /// Set the password for this entry.  Any other platform-specific
    /// annotations are determined by the mapper that was used
    /// to create the credential.
    pub fn set_password(&self, password: &str) -> Result<()> {
        platform::set_password(&self.target, password)
    }

    /// Retrieve the password saved for this entry.
    /// Returns a `NoEntry` error is there isn't one.
    pub fn get_password(&self) -> Result<String> {
        let mut map = self.target.clone();
        platform::get_password(&mut map)
    }

    /// Retrieve the password and all the other fields
    /// set in the platform-specific credential.  This
    /// allows retrieving metadata on the credential that
    /// were saved by external applications.
    pub fn get_password_and_credential(&self) -> Result<(String, PlatformCredential)> {
        let mut map = self.target.clone();
        let password = platform::get_password(&mut map)?;
        Ok((password, map))
    }

    /// Delete the password for this entry.  (Although the entry
    /// itself follows the Rust structure lifecycle, deleting
    /// the password deletes the platform credential from secure storage.)
    pub fn delete_password(&self) -> Result<()> {
        platform::delete_password(&self.target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::default_target;

    #[test]
    fn test_default_initial_and_retrieved_map() {
        let name = generate_random_string();
        let expected_target = default_target(&platform(), None, &name, &name);
        let entry = Entry::new(&name, &name);
        assert_eq!(entry.target, expected_target);
        entry.set_password("ignored").unwrap();
        let (_, target) = entry.get_password_and_credential().unwrap();
        assert_eq!(target, expected_target);
        // don't leave password around.
        entry.delete_password().unwrap();
    }

    #[test]
    fn test_targeted_initial_and_retrieved_map() {
        let name = generate_random_string();
        let expected_target = default_target(&platform(), Some(&name), &name, &name);
        let entry = Entry::new_with_target(&name, &name, &name);
        assert_eq!(entry.target, expected_target);
        // can only test targeted credentials on Windows
        if matches!(platform(), Platform::Windows) {
            entry.set_password("ignored").unwrap();
            let (_, target) = entry.get_password_and_credential().unwrap();
            assert_eq!(target, expected_target);
            // don't leave password around.
            entry.delete_password().unwrap();
        }
    }

    fn generate_random_string() -> String {
        // from the Rust Cookbook:
        // https://rust-lang-nursery.github.io/rust-cookbook/algorithms/randomness.html
        use rand::{distributions::Alphanumeric, thread_rng, Rng};
        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(30)
            .map(char::from)
            .collect()
    }
}
