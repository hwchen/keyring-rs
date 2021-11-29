/*!

Defines a platform-independent error model.

 */

#[derive(Debug)]
/// Each variant of the `Error` enum provides a summary of the error.
/// More details, if relevant, are contained in the associated value,
/// which may be platform-specific.
pub enum Error {
    /// This indicates runtime failure in the underlying
    /// platform storage system.  The details of the failure can
    /// be retrieved from the attached platform error.
    PlatformFailure(crate::platform::Error),
    /// This indicates that the underlying secure storage
    /// holding saved items could not be accessed.  Typically this
    /// is because of access rules in the platform; for example, it
    /// might be that the credential store is locked.  The underlying
    /// platform error will typically give the reason.
    NoStorageAccess(crate::platform::Error),
    /// This indicates that there is no underlying credential
    /// entry in the platform for this entry.  Either one was
    /// never set, or it was deleted.
    NoEntry,
    /// This indicates that the retrieved password blob was not
    /// a UTF-8 string.  The underlying bytes are available
    /// for examination in the attached value.
    BadEncoding(Vec<u8>),
    /// This indicates that one of the entry's credential
    /// attributes exceeded a
    /// length limit in the underlying platform.  The
    /// attached values give the name of the attribute and
    /// the platform length limit that was exceeded.
    TooLong(String, u32),
    /// This indicates that the credential provided
    /// to `Entry::new_with_credential` was for
    /// a different platform than the one in use.
    WrongCredentialPlatform,
}

pub type Result<T> = std::result::Result<T, Error>;

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::WrongCredentialPlatform => {
                write!(f, "CredentialMapper value doesn't match this platform")
            }
            Error::PlatformFailure(err) => write!(f, "Platform secure storage failure: {}", err),
            Error::NoStorageAccess(err) => {
                write!(f, "Couldn't access platform secure storage: {}", err)
            }
            Error::NoEntry => write!(f, "No matching entry found in secure storage"),
            Error::BadEncoding(_) => write!(f, "Password cannot be UTF-8 encoded"),
            Error::TooLong(name, len) => write!(
                f,
                "Attribute '{}' is longer than platform limit of {} chars",
                name, len
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::PlatformFailure(err) => Some(err),
            Error::NoStorageAccess(err) => Some(err),
            _ => None,
        }
    }
}
