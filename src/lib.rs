//! # Keyring library
//!
//! Allows for setting and getting passwords on Linux, OSX, and Windows

// Configure for Linux
#[cfg(target_os = "linux")]
extern crate secret_service;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::Keyring;

// Configure for Windows
#[cfg(target_os = "windows")]
extern crate winapi;
#[cfg(target_os = "windows")]
extern crate advapi32;
#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::Keyring;

// Configure for OSX
#[cfg(target_os = "macos")]
extern crate rustc_serialize;
#[cfg(target_os = "macos")]
extern crate security_framework;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::Keyring;

mod error;
pub use error::{KeyringError, Result};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_password_input() {
        let pass = "";
        let keyring = Keyring::new("test", "test");
        keyring.set_password(pass).unwrap();
        let out = keyring.get_password().unwrap();
        keyring.delete_password().unwrap();
        assert_eq!(pass, out);
    }
}
