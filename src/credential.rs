/*
This crate has a very simple model of a keyring: it has any number
of items, each of which is identified by a <username, service> pair,
has no other metadata, and has a UTF-8 string as its "password".
Furthermore, there is only one keyring.

This crate runs on several different platforms, each of which has its
own secure storage system with its own model for what constitutes a
"generic" secure credential: where it is stored, how it is identified,
what metadata it has, and what kind of "password" it allows.  These
platform credentials provide the persistence for keyring items.

In order to bridge the gap between the keyring item model and each
platform's credential model, this crate uses a "credential mapper":
a function which maps from keyring items to platform credentials.
The inputs to a credential mapper are the platform, username, and
service of the keyring item; its output is a platform-specific
"recipe" for identifying and annotating the credential which the
crate will use to store the item's password.

This module provides a credential model for each supported platform,
and a credential mapper which the crate uses by default.  Clients
who want to use a different credential mapper can provide their own,
which allows this crate to operate compatibly with the conventions
used by third-party applications. For example:

* On Windows, generic credentials are identified by an arbitrary string,
and this crate uses "service.username" as that string.  Most 3rd party
applications, on the other hand, use the service name as the identifying
string and keep the username as a metadata attribute on the credential.

* On Linux and Mac, there are multiple credential stores for each OS user.
Some 3rd party applications don't use the "default" store for their data.

 */

use std::collections::HashMap;

#[derive(Debug)]
pub enum Platform {
    Linux,
    Windows,
    MacOs,
}

// Linux supports multiple credential stores, each named by a string.
// Credentials in a store are identified by an arbitrary collection
// of attributes, and each can have "label" metadata for use in
// graphical editors.
#[derive(Debug, Clone)]
pub struct LinuxCredential {
    pub collection: String,
    pub attributes: HashMap<String, String>,
    pub label: String,
}

impl LinuxCredential {
    // Using strings in the credential map makes managing the lifetime
    // of the credential much easier.  But since the secret service expects
    // a map from &str to &str, we have this utility to transform the
    // credential's map into one of the right form.
    pub fn attributes(&self) -> HashMap<&str, &str> {
        self.attributes
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect()
    }
}

// Windows has only one credential store, and each credential is identified
// by a single string called the "target name".  But generic credentials
// also have three pieces of metadata with suggestive names.
#[derive(Debug, Clone)]
pub struct WinCredential {
    pub username: String,
    pub target_name: String,
    pub target_alias: String,
    pub comment: String,
}

// MacOS supports multiple OS-provided credential stores, and used to support creating
// arbitrary new credential stores (but that has been deprecated).  Credentials on
// Mac also can have "type" but we don't reflect that here because the type is actually
// opaque once set and is only used in the Keychain UI.
#[derive(Debug, Clone)]
pub struct MacCredential {
    pub domain: MacKeychainDomain,
    pub service: String,
    pub account: String,
}

#[derive(Debug, Clone)]
pub enum MacKeychainDomain {
    User,
    System,
    Common,
    Dynamic,
}

#[derive(Debug, Clone)]
pub enum PlatformCredential {
    Linux(LinuxCredential),
    Win(WinCredential),
    Mac(MacCredential),
}

impl PlatformCredential {
    pub fn matches_platform(&self, os: &Platform) -> bool {
        match self {
            PlatformCredential::Linux(_) => matches!(os, Platform::Linux),
            PlatformCredential::Mac(_) => matches!(os, Platform::MacOs),
            PlatformCredential::Win(_) => matches!(os, Platform::Windows),
        }
    }
}

// The signature of a credential mapper (see the module documentation for details).
// TODO: Make this a Fn trait so we can accept closures
pub type CredentialMapper = fn(&Platform, &str, &str) -> PlatformCredential;

// The default credential mapper used by this crate, which maps keyring items
// to credentials in the "default" store on each platform, identified uniquely
// by the pair <service.username>, and carrying simple metadata where appropriate.
pub fn default_mapper(platform: Platform, service: &str, username: &str) -> PlatformCredential {
    match platform {
        Platform::Linux => PlatformCredential::Linux(LinuxCredential {
            collection: "default".to_string(),
            attributes: HashMap::from([
                ("service".to_string(), service.to_string()),
                ("username".to_string(), username.to_string()),
                ("application".to_string(), "rust-keyring".to_string()),
            ]),
            label: format!(
                "keyring-rs credential for service '{}', user '{}'",
                service, username
            ),
        }),
        Platform::Windows => PlatformCredential::Win(WinCredential {
            // Note: default concatenation of user and service name is
            // needed because windows identity is on target_name only
            // See issue here: https://github.com/jaraco/keyring/issues/47
            username: username.to_string(),
            target_name: format!("{}.{}", username, service),
            target_alias: String::new(),
            comment: format!(
                "keyring-rs credential for service '{}', user '{}'",
                service, username
            ),
        }),
        Platform::MacOs => PlatformCredential::Mac(MacCredential {
            domain: MacKeychainDomain::User,
            service: service.to_string(),
            account: username.to_string(),
        }),
    }
}
