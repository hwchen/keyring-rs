#[cfg(target_os = "linux")]
use secret_service::SsError;
#[cfg(target_os = "macos")]
use security_framework::base::Error as SfError;
use std::error;
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
    Parse(FromUtf8Error),
}

impl fmt::Display for KeyringError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            #[cfg(target_os = "macos")]
            KeyringError::MacOsKeychainError(ref err) => write!(f, "Mac Os Keychain Error: {}", err),
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

    fn cause(&self) -> Option<&error::Error> {
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
        KeyringError::Parse(err)
    }
}
