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

#[cfg(doctest)]
doc_comment::doctest!("../README.md");

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    static TEST_SERVICE: &str = "test.keychain-rs.io";
    static TEST_USER: &str = "user@keychain-rs.io";
    static TEST_ASCII_PASSWORD: &str = "my_password";
    static TEST_NON_ASCII_PASSWORD: &str = "大根";

    #[test]
    #[serial]
    fn test_empty_keyring() {
        let service = generate_random_string();
        let username = generate_random_string();
        let keyring = Entry::new(&service, &username);
        assert!(
            keyring.get_password().is_err(),
            "Read a password from a non-existent platform item"
        )
    }

    #[test]
    #[serial]
    fn test_empty_password_input() {
        let pass = "";
        let keyring = Entry::new("test", "test");
        keyring.set_password(pass).unwrap();
        let out = keyring.get_password().unwrap();
        assert_eq!(pass, out, "Stored and retrieved passwords don't match");
        keyring.delete_password().unwrap();
        assert!(
            keyring.get_password().is_err(),
            "Able to read a deleted password"
        )
    }

    #[test]
    #[serial]
    fn test_round_trip_ascii_password() {
        let keyring = Entry::new(TEST_SERVICE, TEST_USER);
        keyring.set_password(TEST_ASCII_PASSWORD).unwrap();
        let stored_password = keyring.get_password().unwrap();
        assert_eq!(stored_password, TEST_ASCII_PASSWORD);
        keyring.delete_password().unwrap();
        assert!(
            keyring.get_password().is_err(),
            "Able to read a deleted password"
        )
    }

    #[test]
    #[serial]
    fn test_round_trip_non_ascii_password() {
        let keyring = Entry::new(TEST_SERVICE, TEST_USER);
        keyring.set_password(TEST_NON_ASCII_PASSWORD).unwrap();
        let stored_password = keyring.get_password().unwrap();
        assert_eq!(stored_password, TEST_NON_ASCII_PASSWORD);
        keyring.delete_password().unwrap();
        assert!(
            keyring.get_password().is_err(),
            "Able to read a deleted password"
        )
    }

    // TODO: write tests for erroneous input
    // This might be better done in a separate test file.

    // TODO: write tests for custom mappers.
    // This might be better done in a separate test file.

    // utility
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
