//! # Keyring library
//!
//! Allows for setting and getting passwords on Linux, OSX, and Windows

mod credential;
mod error;

pub use credential::{CredentialMapper, Platform, PlatformCredential};
pub use error::{Error, Result};

// compile-time Platform known at runtime
fn platform() -> Platform {
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
    // Create a new entry for the given service and username.
    // This uses the module-default mapper.  If the defaults don't
    // work for your application, you can construct your own
    // algorithm and use `new_with_mapper`.
    pub fn new(service: &str, username: &str) -> Entry {
        Entry {
            target: credential::default_mapper(platform(), service, username),
        }
    }

    // Create a new item using a client-supplied mapper
    // for interoperability with credentials written by
    // other applications.
    pub fn new_with_mapper(
        service: &str,
        username: &str,
        mapper: CredentialMapper,
    ) -> Result<Entry> {
        let os = platform();
        let map = mapper(&os, service, username);
        if map.matches_platform(&os) {
            Ok(Entry { target: map })
        } else {
            Err(Error::WrongCredentialPlatform)
        }
    }

    // Set the password for this item.  Any other platform-specific
    // annotations are determined by the mapper that was used
    // to create the credential.
    pub fn set_password(&self, password: &str) -> Result<()> {
        platform::set_password(&self.target, password)
    }

    // Retrieve the password saved for this item.
    // Returns a `NoEntry` error is there isn't one.
    pub fn get_password(&self) -> Result<String> {
        let mut map = self.target.clone();
        platform::get_password(&mut map)
    }

    // Retrieve the password and all the other fields
    // set in the platform-specific credential.  This
    // allows retrieving metdata on the credential that
    // were saved by external applications.
    pub fn get_password_and_credential(&self) -> Result<(String, PlatformCredential)> {
        let mut map = self.target.clone();
        let password = platform::get_password(&mut map)?;
        Ok((password, map))
    }

    // Delete the password for this item.  (Although the item
    // itself follows the Rust structure lifecycle, deleting
    // the password deletes the platform credential from secure storage.)
    pub fn delete_password(&self) -> Result<()> {
        platform::delete_password(&self.target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::{
        default_mapper, LinuxCredential, MacCredential, MacKeychainDomain, WinCredential,
    };
    use serial_test::serial;
    use std::collections::HashMap;

    #[test]
    #[serial]
    fn test_default_initial_and_retrieved_map() {
        let username = "username";
        let service = "service";
        let expected_target = default_mapper(platform(), service, username);
        let entry = Entry::new(service, username);
        assert_eq!(
            entry.target, expected_target,
            "Entry doesn't have default map"
        );
        entry.set_password("ignored").unwrap();
        let (_, target) = entry.get_password_and_credential().unwrap();
        assert_eq!(
            target, expected_target,
            "Retrieved entry doesn't have default map"
        );
    }

    fn constant_mapper(platform: Platform, _: &str, _: &str) -> PlatformCredential {
        match platform {
            Platform::Linux => PlatformCredential::Linux(LinuxCredential {
                collection: "default".to_string(),
                attributes: HashMap::from([
                    ("service".to_string(), "service".to_string()),
                    ("username".to_string(), "username".to_string()),
                    ("application".to_string(), "application".to_string()),
                    ("additional".to_string(), "additional".to_string()),
                ]),
                label: "constant label".to_string(),
            }),
            Platform::Windows => PlatformCredential::Win(WinCredential {
                // Note: default concatenation of user and service name is
                // needed because windows identity is on target_name only
                // See issue here: https://github.com/jaraco/keyring/issues/47
                username: "username".to_string(),
                target_name: "target_name".to_string(),
                target_alias: "target_alias".to_string(),
                comment: "constant comment".to_string(),
            }),
            Platform::MacOs => PlatformCredential::Mac(MacCredential {
                domain: MacKeychainDomain::User,
                service: "service".to_string(),
                account: "username".to_string(),
            }),
        }
    }

    #[test]
    #[serial]
    fn test_custom_initial_and_retrieved_map() {
        let username = "username";
        let service = "service";
        let expected_target = constant_mapper(platform(), service, username);
        let entry = Entry::new(service, username);
        assert_eq!(
            entry.target, expected_target,
            "Entry doesn't have expected map"
        );
        entry.set_password("ignored").unwrap();
        let (_, target) = entry.get_password_and_credential().unwrap();
        assert_eq!(
            target, expected_target,
            "Retrieved entry doesn't have expected map"
        );
    }
}
