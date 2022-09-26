use crate::error::decode_password;
use crate::{Error as ErrorCode, Platform, PlatformCredential, Result};
use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};

pub fn platform() -> Platform {
    Platform::Ios
}

pub use security_framework::base::Error;

/// iOS credentials all go in the user keychain identified by service and account.
#[derive(Debug, Clone, PartialEq, Eq)]
struct IosCredential {
    pub service: String,
    pub account: String,
}

/// Create the default target credential for a keyring entry.  The caller
/// can provide an optional target parameter to influence the mapping.
///
/// If any of the provided strings are empty, the credential returned is
/// invalid, to prevent it being used.  This is because platform behavior
/// around empty strings for attributes is undefined.
pub fn default_target(
    platform: &Platform,
    target: Option<&str>,
    service: &str,
    username: &str,
) -> PlatformCredential {
    if service.is_empty() || username.is_empty() || target.unwrap_or("none").is_empty() {
        return PlatformCredential::Invalid;
    }
    const VERSION: &str = env!("CARGO_PKG_VERSION");
    let custom = if target.is_none() {
        "entry"
    } else {
        "custom entry"
    };
    let metadata = format!(
        "keyring-rs v{} {} for service '{}', user '{}'",
        VERSION, custom, service, username
    );
    match platform {
        Platform::Linux => PlatformCredential::Linux(LinuxCredential {
            collection: target.unwrap_or("default").to_string(),
            attributes: HashMap::from([
                ("service".to_string(), service.to_string()),
                ("username".to_string(), username.to_string()),
                ("application".to_string(), "rust-keyring".to_string()),
            ]),
            label: metadata,
        }),
        Platform::Windows => {
            if let Some(keychain) = target {
                PlatformCredential::Win(WinCredential {
                    // Note: Since Windows doesn't support multiple keychains,
                    // and since it's nice for clients to have control over
                    // the target_name directly, we use the `keychain` value
                    // as the target name if it's specified non-default.
                    username: username.to_string(),
                    target_name: keychain.to_string(),
                    target_alias: String::new(),
                    comment: metadata,
                })
            } else {
                PlatformCredential::Win(WinCredential {
                    // Note: default concatenation of user and service name is
                    // used because windows uses target_name as sole identifier.
                    // See the README for more rationale.  Also see this issue
                    // for Python: https://github.com/jaraco/keyring/issues/47
                    username: username.to_string(),
                    target_name: format!("{}.{}", username, service),
                    target_alias: String::new(),
                    comment: metadata,
                })
            }
        }
        Platform::MacOs => PlatformCredential::Mac(MacCredential {
            domain: target.into(),
            service: service.to_string(),
            account: username.to_string(),
        }),
        Platform::Ios => PlatformCredential::Ios(IosCredential {
            service: service.to_string(),
            account: username.to_string(),
        }),
    }
}

pub fn set_password(map: &PlatformCredential, password: &str) -> Result<()> {
    if let PlatformCredential::Ios(map) = map {
        set_generic_password(&map.service, &map.account, password.as_bytes())
            .map_err(decode_error)?;
        Ok(())
    } else {
        Err(ErrorCode::WrongCredentialPlatform)
    }
}

pub fn get_password(map: &mut PlatformCredential) -> Result<String> {
    if let PlatformCredential::Ios(map) = map {
        let password_bytes =
            get_generic_password(&map.service, &map.account).map_err(decode_error)?;
        decode_password(password_bytes.to_vec())
    } else {
        Err(ErrorCode::WrongCredentialPlatform)
    }
}

pub fn delete_password(map: &PlatformCredential) -> Result<()> {
    if let PlatformCredential::Ios(map) = map {
        delete_generic_password(&map.service, &map.account).map_err(decode_error)?;
        Ok(())
    } else {
        Err(ErrorCode::WrongCredentialPlatform)
    }
}

/// The Ios error codes used here are from:
/// https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-78/lib/SecBase.h.auto.html
fn decode_error(err: Error) -> ErrorCode {
    match err.code() {
        -25291 => ErrorCode::NoStorageAccess(err), // errSecNotAvailable
        -25292 => ErrorCode::NoStorageAccess(err), // errSecReadOnly
        -25300 => ErrorCode::NoEntry,              // errSecItemNotFound
        _ => ErrorCode::PlatformFailure(err),
    }
}
