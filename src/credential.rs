/*!

Defines the credential model for each supported platform.

This crate has a very simple model of a keyring: it has any number
of entries, each of which is identified by a <username, service> pair,
has no other metadata, and has a UTF-8 string as its "password".
Furthermore, there is only one keyring.

This crate runs on several different platforms, each of which has its
own secure storage system with its own model for what constitutes a
"generic" secure credential: where it is stored, how it is identified,
what metadata it has, and what kind of "password" it allows.  These
platform credentials provide the persistence for keyring entries.

In order to bridge the gap between the keyring entry model and each
platform's credential model, this crate uses a "credential mapper":
a function which maps from keyring entries to platform credentials.
The inputs to a credential mapper are the platform, optional target
specification, service, and username of the keyring entry; its output
is a platform-specific "recipe" for identifying and annotating the
platform credential which the crate will use for this entry.

This module provides a credential model for each supported platform,
and a credential mapper which the crate uses by default.  The default
credential mapper can be "advised" by providing a suggested "target"
when creating an entry: on Linux and Mac this target is interpreted
as the collection/keychain to put the credential in; on Windows this
target is taken literally as the "target name" of the credential.

Clients who want to use a different algorithm for mapping service/username
pairs to platform credentials can also provide the specific credential spec
they want to use when creating the entry.

See the [top-level library documentation](https://docs.rs/keyring) for
more information about the platform-specific credential mapping.
Or read the code here :).

 */

use std::collections::HashMap;

/// The supported platforms.
#[derive(Debug)]
pub enum Platform {
    Linux,
    Windows,
    MacOs,
    Ios,
}

/// Linux supports multiple credential stores, each named by a string.
/// Credentials in a store are identified by an arbitrary collection
/// of attributes, and each can have "label" metadata for use in
/// graphical editors.
#[derive(Debug, Clone, PartialEq)]
pub struct LinuxCredential {
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

/// Windows has only one credential store, and each credential is identified
/// by a single string called the "target name".  But generic credentials
/// also have three pieces of metadata with suggestive names.
#[derive(Debug, Clone, PartialEq)]
pub struct WinCredential {
    pub username: String,
    pub target_name: String,
    pub target_alias: String,
    pub comment: String,
}

/// MacOS supports multiple OS-provided credential stores, and used to support creating
/// arbitrary new credential stores (but that has been deprecated).  Credentials on
/// Mac also can have "type" but we don't reflect that here because the type is actually
/// opaque once set and is only used in the Keychain UI.
#[derive(Debug, Clone, PartialEq)]
pub struct MacCredential {
    pub domain: MacKeychainDomain,
    pub service: String,
    pub account: String,
}

#[derive(Debug, Clone, PartialEq)]
/// There are four pre-defined Mac keychains.  Now that file-based keychains are
/// deprecated, those are the only domains that can be accessed.
pub enum MacKeychainDomain {
    User,
    System,
    Common,
    Dynamic,
}

impl From<&str> for MacKeychainDomain {
    /// Target specifications are strings, but on Mac we map them
    /// to keychoin domains.  We accept any case in the string,
    /// but the value has to match a known keychain domain name
    /// or else we assume the login keychain is meant.
    fn from(keychain: &str) -> Self {
        match keychain.to_ascii_lowercase().as_str() {
            "system" => MacKeychainDomain::System,
            "common" => MacKeychainDomain::Common,
            "dynamic" => MacKeychainDomain::Dynamic,
            _ => MacKeychainDomain::User,
        }
    }
}

impl From<Option<&str>> for MacKeychainDomain {
    fn from(keychain: Option<&str>) -> Self {
        match keychain {
            None => MacKeychainDomain::User,
            Some(str) => str.into(),
        }
    }
}

/// iOS credentials all go in the user keychain identified by service and account.
#[derive(Debug, Clone, PartialEq)]
pub struct IosCredential {
    pub service: String,
    pub account: String,
}

#[derive(Debug, Clone, PartialEq)]
/// While defined cross-platform, instantiated platform
/// credentials always contain just the model for the
/// current runtime `Platform`.
/// 
/// Because you can create credentials for any strings,
/// but platform handling of empty target attributes is
/// not well defined, we have a special Invalid case
/// which we use in this case to ensure the created
/// credential has no functionality. 
pub enum PlatformCredential {
    Linux(LinuxCredential),
    Win(WinCredential),
    Mac(MacCredential),
    Ios(IosCredential),
    Invalid,
}

impl PlatformCredential {
    pub fn matches_platform(&self, os: &Platform) -> bool {
        match self {
            PlatformCredential::Linux(_) => matches!(os, Platform::Linux),
            PlatformCredential::Win(_) => matches!(os, Platform::Windows),
            PlatformCredential::Mac(_) => matches!(os, Platform::MacOs),
            PlatformCredential::Ios(_) => matches!(os, Platform::Ios),
            PlatformCredential::Invalid => false,
        }
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
