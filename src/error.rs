use std::string::{FromUtf16Error, FromUtf8Error};

use thiserror::Error;

#[cfg(target_os = "linux")]
use secret_service::Error as OsError;
#[cfg(target_os = "macos")]
use security_framework::base::Error as OsError;
#[cfg(target_os = "windows")]
use windows::Error as OsError;

pub type Result<T> = ::std::result::Result<T, KeyringError>;

#[derive(Debug, Error)]
pub enum KeyringError {
    #[error("OS Error message {:?}", os_error(.0))]
    OsError(#[from] OsError),
    #[error("No Backend found")]
    NoBackendFound,
    #[error("No Password found")]
    NoPasswordFound,
    #[error("Parsing error")]
    Parse(#[from] ParseError),
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("from utf8")]
    Utf8(#[from] FromUtf8Error),
    #[error("from utf16")]
    Utf16(#[from] FromUtf16Error),
}

fn os_error(e: &OsError) -> String {
    #[cfg(target_os = "macos")]
    {
        e.message().unwrap_or_else(|| "no message".to_string())
    }
    #[cfg(target_os = "linux")]
    {
        let _e = e;
        "no message".to_string()
    }
    #[cfg(target_os = "windows")]
    {
        e.message()
    }
}
