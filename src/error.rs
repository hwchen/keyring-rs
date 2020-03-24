// TODO real error handling
// Better unify errors so I don't have os-specific errors for important ones
// like no password found.
// Less important ones can get a description and put into Other
//
// Consider using thiserror
//
// ```
// pub enum KeyringError {
//     NoBackendFound,
//     NoLogonSession, // windows has this, do linux and macos?
//     NoPasswordcFound,
//     Parse(FromUtf8Error),
//     Other(String), // use this for things like windows ERROR_INVALID_FLAGS
// }
// ```
//
// ## Possible errors:
//
// Windows:
// Call GetLastError in order to get error code to match.
//
// https://docs.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-creddeletew
// - ERROR_NOT_FOUND
// - ERROR_NO_SUCH_LOGON_SESSION
// - ERROR_INVALID_FLAGS
//
// https://docs.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credreadw
// - ERROR_NOT_FOUND
// - ERROR_NO_SUCH_LOGON_SESSION
// - ERROR_INVALID_FLAGS
// - invalid utf8 error
//
// https://docs.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credwritew
// - ERROR_NO_SUCH_LOGON_SESSION
// - ERROR_INVALID_PARAMETER
// - ERROR_INVALID_FLAGS
// - ERROR_BAD_USERNAME
// - ERROR_NOT_FOUND
// - SCARD_E_NO_SMARTCARD
// - SCARD_W_REMOVED_CARD
// - SCARD_WRONG_CHV
//
// MacOs
// Match on Error.code() (OSStatus)
// https://docs.rs/security-framework/0.4.2-alpha.1/security_framework/base/struct.Error.html
// https://developer.apple.com/documentation/security/1542001-security_framework_result_codes?language=objc
// Check list for all the i32 codes.
// e.g.
// https://developer.apple.com/documentation/security/1542001-security_framework_result_codes/errsecitemnotfound?language=objc
// errSecItemNotFound, -25300
//
// Linux
// Most secret service errors are currently transmitted as Dbus errors.
// https://specifications.freedesktop.org/secret-service/latest/ch15.html
// - IsLocked
// - NoSession
// - NoSuchObject
//
// I probably need to reconsider cleaning up secret service errors also.

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
