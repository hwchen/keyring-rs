#[derive(Debug)]
pub enum ErrorCode {
    BadCredentialMapPlatform,
    PlatformFailure,
    NoStorageAccess,
    NoEntry,
    BadEncoding(String, Vec<u8>),
    TooLong(String, u32),
}

#[derive(Debug)]
pub struct Error {
    pub code: ErrorCode,
    pub platform: Option<crate::platform::Error>,
}

pub type Result<T> = std::result::Result<T, Error>;

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let message = match &self.code {
            ErrorCode::BadCredentialMapPlatform => {
                "CredentialMapper value doesn't match this platform".to_string()
            }
            ErrorCode::PlatformFailure => "Platform secure storage failure".to_string(),
            ErrorCode::NoStorageAccess => "Couldn't access platform secure storage".to_string(),
            ErrorCode::NoEntry => "No matching entry found in secure storage".to_string(),
            ErrorCode::BadEncoding(name, _) => {
                format!("Attribute '{}' cannot be encoded as a Rust string", &name)
            }
            ErrorCode::TooLong(name, len) => format!(
                "Attribute '{}' is longer than platform limit of {} chars",
                &name, len
            ),
        };
        if let Some(platform_error) = &self.platform {
            write!(f, "{}: {}", message, platform_error)
        } else {
            write!(f, "{}", message)
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(platform_error) = self.platform.as_ref() {
            Some(platform_error)
        } else {
            None
        }
    }
}

impl Error {
    pub fn new(code: ErrorCode) -> Error {
        Error {
            code,
            platform: None,
        }
    }
    pub fn new_from_platform(code: ErrorCode, err: crate::platform::Error) -> Error {
        Error {
            code,
            platform: Some(err),
        }
    }
}

impl From<Error> for ErrorCode {
    fn from(err: Error) -> Self {
        err.code
    }
}

impl From<ErrorCode> for Error {
    fn from(code: ErrorCode) -> Self {
        Error::new(code)
    }
}
