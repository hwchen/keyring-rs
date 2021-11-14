//! # Keyring library
//!
//! Allows for setting and getting passwords on Linux, OSX, and Windows

mod attrs;
mod error;

pub use attrs::{CredentialMapper, Platform, PlatformCredential};
pub use error::{Error, ErrorCode, Result};

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
pub struct Keyring {
    map: PlatformCredential,
}

impl Keyring {
    // Create a new keyring for the given service and username.
    // This uses the module-default algorithm for filling the
    // platform-specific fields appropriately.  If these don't
    // work for your application, you can construct your own
    // algorithm and use `new_with_mapper`.
    pub fn new(service: &str, username: &str) -> Keyring {
        Keyring {
            map: attrs::default_credential_mapper(platform(), service, username),
        }
    }

    // Create a new keyring using a client-supplied algorithm
    // for setting the platform-specific credential fields.
    pub fn new_with_mapper(
        service: &str,
        username: &str,
        mapper: CredentialMapper,
    ) -> Result<Keyring> {
        let os = platform();
        let map = mapper(&os, service, username);
        if map.matches_platform(&os) {
            Ok(Keyring { map })
        } else {
            Err(ErrorCode::BadCredentialMapPlatform.into())
        }
    }

    pub fn set_password(&self, password: &str) -> Result<()> {
        platform::set_password(&self.map, password)
    }

    pub fn get_password(&self) -> Result<String> {
        let mut map = self.map.clone();
        platform::get_password(&mut map)
    }

    pub fn get_password_and_credential(&self) -> Result<(String, PlatformCredential)> {
        let mut map = self.map.clone();
        let password = platform::get_password(&mut map)?;
        Ok((password, map))
    }

    pub fn delete_password(&self) -> Result<()> {
        platform::delete_password(&self.map)
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
        let keyring = Keyring::new(&service, &username);
        assert!(
            keyring.get_password().is_err(),
            "Read a password from a non-existent platform item"
        )
    }

    #[test]
    #[serial]
    fn test_empty_password_input() {
        let pass = "";
        let keyring = Keyring::new("test", "test");
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
        let keyring = Keyring::new(TEST_SERVICE, TEST_USER);
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
        let keyring = Keyring::new(TEST_SERVICE, TEST_USER);
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
