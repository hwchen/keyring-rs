use std::str::Utf8Error;
use std::string::FromUtf8Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum KeyringError {
    BadEncoding,
    BadIdentityMapPlatform,
    PlatformFailure,
    NoStorage,
    NoEntry,
}

#[derive(Debug)]
pub struct Error {
    pub code: KeyringError,
    pub platform: Option<crate::platform::Error>,
    pub encoding: Option<Utf8Error>,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let fstring = match self.code {
            KeyringError::BadIdentityMapPlatform => {
                "IdentityMapper value doesn't match this platform"
            }
            KeyringError::PlatformFailure => "Platform secure storage failure",
            KeyringError::NoStorage => "Couldn't access platform secure storage",
            KeyringError::NoEntry => "No matching entry found in secure storage",
            KeyringError::BadEncoding => "Password data was not UTF-8 encoded",
        };
        if let Some(platform_error) = self.platform {
            write!(f, "{}: {}", fstring, platform_error)
        } else if let Some(encoding_error) = self.encoding {
            write!(f, "{}: {}", fstring, encoding_error)
        } else {
            write!(f, "{}", fstring)
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(platform_error) = self.platform.as_ref() {
            Some(platform_error)
        } else if let Some(encoding_error) = self.encoding.as_ref() {
            Some(encoding_error)
        } else {
            None
        }
    }
}

impl Error {
    pub fn new(code: KeyringError) -> Error {
        Error {
            code,
            platform: None,
            encoding: None,
        }
    }
    pub fn new_from_encoding(err: Utf8Error) -> Error {
        Error {
            code: KeyringError::BadEncoding,
            platform: None,
            encoding: Some(err),
        }
    }
    pub fn new_from_platform(code: KeyringError, err: crate::platform::Error) -> Error {
        Error {
            code,
            platform: Some(err),
            encoding: None,
        }
    }
}

impl From<Error> for KeyringError {
    fn from(err: Error) -> Self {
        err.code
    }
}

impl From<KeyringError> for Error {
    fn from(code: KeyringError) -> Self {
        Error::new(code)
    }
}

impl From<FromUtf8Error> for Error {
    fn from(err: FromUtf8Error) -> Error {
        Error::new_from_encoding(err.utf8_error())
    }
}
