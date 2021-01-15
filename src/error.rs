#[cfg(target_os = "linux")]
use secret_service::SsError;
#[cfg(target_os = "macos")]
use security_framework::base::Error as SfError;
use std::{error, string::FromUtf16Error};
use std::fmt;
use std::string::FromUtf8Error;

pub type Result<T> = ::std::result::Result<T, KeyringError>;

#[derive(Debug)]
pub enum KeyringError {
    #[cfg(target_os = "macos")]
    MacOsKeychainError(SfError),
    #[cfg(target_os = "linux")]
    SecretServiceError(SsError),
    #[cfg(target_os = "windows")]
    WindowsVaultError,
    NoBackendFound,
    NoPasswordFound,
    /// Parse errors are errors that occur when trying to parse the password
    /// from the credential storage.
    Parse(ParseError),
}

impl fmt::Display for KeyringError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            #[cfg(target_os = "macos")]
            KeyringError::MacOsKeychainError(ref err) => {
                write!(f, "Mac Os Keychain Error: {}", err)
            }
            #[cfg(target_os = "linux")]
            KeyringError::SecretServiceError(ref err) => write!(f, "Secret Service Error: {}", err),
            #[cfg(target_os = "windows")]
            KeyringError::WindowsVaultError => write!(f, "Windows Vault Error"),
            KeyringError::NoBackendFound => write!(f, "Keyring error: No Backend Found"),
            KeyringError::NoPasswordFound => write!(f, "Keyring Error: No Password Found"),
            KeyringError::Parse(ref err) => write!(f, "Keyring Parse Error: {}", err),
        }
    }
}

impl error::Error for KeyringError {
    fn description(&self) -> &str {
        match *self {
            #[cfg(target_os = "macos")]
            KeyringError::MacOsKeychainError(ref err) => err.description(),
            #[cfg(target_os = "linux")]
            KeyringError::SecretServiceError(ref err) => err.description(),
            #[cfg(target_os = "windows")]
            KeyringError::WindowsVaultError => "Windows Vault Error",
            KeyringError::NoBackendFound => "No Backend Found",
            KeyringError::NoPasswordFound => "No Password Found",
            KeyringError::Parse(ref err) => err.description(),
        }
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            #[cfg(target_os = "linux")]
            KeyringError::SecretServiceError(ref err) => Some(err),
            #[cfg(target_os = "macos")]
            KeyringError::MacOsKeychainError(ref err) => Some(err),
            _ => None,
        }
    }
}

#[cfg(target_os = "linux")]
impl From<SsError> for KeyringError {
    fn from(err: SsError) -> KeyringError {
        KeyringError::SecretServiceError(err)
    }
}

#[cfg(target_os = "macos")]
impl From<SfError> for KeyringError {
    fn from(err: SfError) -> KeyringError {
        KeyringError::MacOsKeychainError(err)
    }
}

impl From<FromUtf8Error> for KeyringError {
    fn from(err: FromUtf8Error) -> KeyringError {
        KeyringError::Parse(ParseError::FromUtf8(err))
    }
}

impl From<FromUtf16Error> for KeyringError {
    fn from(err: FromUtf16Error) -> KeyringError {
        KeyringError::Parse(ParseError::FromUtf16(err))
    }
}

/// ParseError is the enumeration of errors that can occur when parsing
/// a password from credential storage.
#[derive(Debug)]
pub enum ParseError {
    /// FromUtf8 is an error that occured when trying to parse the password
    /// as a UTF-8 string
    FromUtf8(FromUtf8Error),
    /// FromUtf16 is an error that occured when trying to parse the password
    /// as a UTF-16 string
    FromUtf16(FromUtf16Error),
}

impl  error::Error for ParseError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ParseError::FromUtf8(e) => Some(e),
            ParseError::FromUtf16(e) => Some(e),
        }
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        self.source()
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::FromUtf8(e) => write!(f, "UTF-8 Error: {}", e),
            ParseError::FromUtf16(e) => write!(f, "UTF-16 Error: {}", e),
        }
    }
}