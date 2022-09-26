use secret_service::{Collection, EncryptionType, Item, SecretService};

use crate::error::decode_password;
use crate::{Error as ErrorCode, Platform, PlatformCredential, Result};

pub fn platform() -> Platform {
    Platform::Linux
}

use crate::credential::LinuxCredential;
pub use secret_service::Error;

/// Linux supports multiple credential stores, each named by a string.
/// Credentials in a store are identified by an arbitrary collection
/// of attributes, and each can have "label" metadata for use in
/// graphical editors.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LinuxCredential {
    pub collection: String,
    pub attributes: HashMap<String, String>,
    pub label: String,
}

impl LinuxCredential {
    /// Using strings in the credential map makes managing the lifetime
    /// of the credential much easier.  But since the secret service expects
    /// a map from &str to &str, we have this utility to transform the
    /// credential's map into one of the right form.
    pub fn attributes(&self) -> HashMap<&str, &str> {
        self.attributes
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect()
    }
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

fn get_collection<'a>(map: &LinuxCredential, ss: &'a SecretService) -> Result<Collection<'a>> {
    let collection = ss
        .get_collection_by_alias(map.collection.as_str())
        .map_err(decode_error)?;
    if collection.is_locked().map_err(decode_error)? {
        collection.unlock().map_err(decode_error)?;
    }
    Ok(collection)
}

pub fn set_password(map: &PlatformCredential, password: &str) -> Result<()> {
    if let PlatformCredential::Linux(map) = map {
        let ss = SecretService::new(EncryptionType::Dh).map_err(ErrorCode::PlatformFailure)?;
        let collection = get_collection(map, &ss)?;
        collection
            .create_item(
                map.label.as_str(),
                map.attributes(),
                password.as_bytes(),
                true, // replace
                "text/plain",
            )
            .map_err(ErrorCode::PlatformFailure)?;
        Ok(())
    } else {
        Err(ErrorCode::WrongCredentialPlatform)
    }
}

pub fn get_password(map: &mut PlatformCredential) -> Result<String> {
    if let PlatformCredential::Linux(map) = map {
        let ss = SecretService::new(EncryptionType::Dh).map_err(decode_error)?;
        let collection = get_collection(map, &ss)?;
        let search = collection
            .search_items(map.attributes())
            .map_err(decode_error)?;
        let item = search.get(0).ok_or(ErrorCode::NoEntry)?;
        let bytes = item.get_secret().map_err(decode_error)?;
        // Linux keyring allows non-UTF8 values, but this library only supports adding UTF8 items
        // to the keyring, so this should only fail if we are trying to retrieve a non-UTF8
        // password that was added to the keyring by another library
        decode_attributes(map, item);
        decode_password(bytes)
    } else {
        Err(ErrorCode::WrongCredentialPlatform)
    }
}

pub fn delete_password(map: &PlatformCredential) -> Result<()> {
    if let PlatformCredential::Linux(map) = map {
        let ss = SecretService::new(EncryptionType::Dh).map_err(decode_error)?;
        let collection = get_collection(map, &ss)?;
        let search = collection
            .search_items(map.attributes())
            .map_err(decode_error)?;
        let item = search.get(0).ok_or(ErrorCode::NoEntry)?;
        item.delete().map_err(decode_error)?;
        Ok(())
    } else {
        Err(ErrorCode::WrongCredentialPlatform)
    }
}

fn decode_error(err: Error) -> ErrorCode {
    match err {
        Error::Crypto(_) => ErrorCode::PlatformFailure(err),
        Error::Zbus(_) => ErrorCode::PlatformFailure(err),
        Error::ZbusMsg(_) => ErrorCode::PlatformFailure(err),
        Error::ZbusFdo(_) => ErrorCode::PlatformFailure(err),
        Error::Zvariant(_) => ErrorCode::PlatformFailure(err),
        Error::Locked => ErrorCode::NoStorageAccess(err),
        Error::NoResult => ErrorCode::NoStorageAccess(err),
        Error::Parse => ErrorCode::PlatformFailure(err),
        Error::Prompt => ErrorCode::NoStorageAccess(err),
    }
}

fn decode_attributes(map: &mut LinuxCredential, item: &Item) {
    if let Ok(label) = item.get_label() {
        map.label = label
    }
}
