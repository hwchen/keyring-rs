//! # Keyring library
//!
//! Allows for setting and getting passwords on Linux, OSX, and Windows

// Configure for Linux
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::Keyring;

// Configure for Windows
#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::Keyring;

// Configure for OSX
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::Keyring;

mod error;
pub use error::{KeyringError, Result};

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    static TEST_SERVICE: &'static str = "test.keychain-rs.io";
    static TEST_USER: &'static str = "user@keychain-rs.io";
    static TEST_ASCII_PASSWORD: &'static str = "my_password";
    static TEST_NON_ASCII_PASSWORD: &'static str = "大根";

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
}
