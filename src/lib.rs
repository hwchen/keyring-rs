//! # Keyring library
//!
//! Allows for setting and getting passwords on Linux, OSX, and Windows

#[cfg(target_os = "linux")]
extern crate secret_service;
#[cfg(target_os = "linux")]
mod linux;

mod error;

pub use error::{KeyringError, Result};

#[cfg(target_os = "macos")]
mod macos{}
#[cfg(target_os = "windows")]
mod windows{}

#[cfg(target_os = "linux")]
pub use linux::Keyring;
#[cfg(target_os = "macos")]
pub use macos::*;
#[cfg(target_os = "windows")]
pub use windows::*;

