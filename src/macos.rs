use security_framework::os::macos::keychain::{SecKeychain, SecPreferencesDomain};
use security_framework::os::macos::passwords::find_generic_password;

use super::credential::{Credential, CredentialApi, CredentialBuilder, CredentialBuilderApi};
use super::error::{decode_password, Error as ErrorCode, Result};

pub use security_framework::base::Error;

/// MacOS supports multiple OS-provided credential stores, and used to support creating
/// arbitrary new credential stores (but that has been deprecated).  Credentials on
/// Mac also can have "type" but we don't reflect that here because the type is actually
/// opaque once set and is only used in the Keychain UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacCredential {
    domain: MacKeychainDomain,
    service: String,
    account: String,
}

impl CredentialApi for MacCredential {
    fn set_password(&self, password: &str) -> Result<()> {
        get_keychain(self)?
            .set_generic_password(&self.service, &self.account, password.as_bytes())
            .map_err(decode_error)?;
        Ok(())
    }

    fn get_password(&self) -> Result<String> {
        let (password_bytes, _) =
            find_generic_password(Some(&[get_keychain(self)?]), &self.service, &self.account)
                .map_err(decode_error)?;
        decode_password(password_bytes.to_vec())
    }

    fn delete_password(&self) -> Result<()> {
        let (_, item) =
            find_generic_password(Some(&[get_keychain(self)?]), &self.service, &self.account)
                .map_err(decode_error)?;
        item.delete();
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl MacCredential {
    /// Create the platform credential for a Mac keychain entry.
    ///
    /// A target string is interpreted as the keychain to use for the entry.
    ///
    /// The builder will fail if the service or user strings are empty.
    /// This is because Mac platform behavior around empty strings for attributes
    /// is that they act as wildcards, so there is no way to look up a specific
    /// credential that has an empty service or user string.
    fn new_with_target(target: Option<&str>, service: &str, user: &str) -> Result<Self> {
        if service.is_empty() {
            return Err(ErrorCode::InvalidArgument(
                "service cannot be empty".to_string(),
            ));
        }
        if user.is_empty() {
            return Err(ErrorCode::InvalidArgument(
                "user cannot be empty".to_string(),
            ));
        }
        let domain = if let Some(target) = target {
            target.parse()?
        } else {
            MacKeychainDomain::User
        };
        Ok(Self {
            domain,
            service: service.to_string(),
            account: user.to_string(),
        })
    }
}

pub struct MacCredentialBuilder {}

pub fn default_credential_builder() -> Box<CredentialBuilder> {
    Box::new(MacCredentialBuilder {})
}

impl CredentialBuilderApi for MacCredentialBuilder {
    fn build(&self, target: Option<&str>, service: &str, user: &str) -> Result<Box<Credential>> {
        match MacCredential::new_with_target(target, service, user) {
            Ok(credential) => Ok(Box::new(credential)),
            Err(err) => Err(err),
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// There are four pre-defined Mac keychains.  Now that file-based keychains are
/// deprecated, those are the only domains that can be accessed.
enum MacKeychainDomain {
    User,
    System,
    Common,
    Dynamic,
}

impl std::fmt::Display for MacKeychainDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MacKeychainDomain::User => "User".fmt(f),
            MacKeychainDomain::System => "System".fmt(f),
            MacKeychainDomain::Common => "Common".fmt(f),
            MacKeychainDomain::Dynamic => "Dynamic".fmt(f),
        }
    }
}

impl std::str::FromStr for MacKeychainDomain {
    type Err = ErrorCode;

    /// Target specifications are strings, but on Mac we self them
    /// to keychoin domains.  We accept any case in the string,
    /// but the value has to match a known keychain domain name
    /// or else we assume the login keychain is meant.
    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "user" => Ok(MacKeychainDomain::User),
            "system" => Ok(MacKeychainDomain::System),
            "common" => Ok(MacKeychainDomain::Common),
            "dynamic" => Ok(MacKeychainDomain::Dynamic),
            _ => Err(ErrorCode::InvalidArgument(format!(
                "Target ({}) must be one of User, System, Common, or Dynamic",
                s
            ))),
        }
    }
}

fn get_keychain(cred: &MacCredential) -> Result<SecKeychain> {
    let domain = match cred.domain {
        MacKeychainDomain::User => SecPreferencesDomain::User,
        MacKeychainDomain::System => SecPreferencesDomain::System,
        MacKeychainDomain::Common => SecPreferencesDomain::Common,
        MacKeychainDomain::Dynamic => SecPreferencesDomain::Dynamic,
    };
    match SecKeychain::default_for_domain(domain) {
        Ok(keychain) => Ok(keychain),
        Err(err) => Err(decode_error(err)),
    }
}

/// The MacOS error codes used here are from:
/// https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-78/lib/SecBase.h.auto.html
fn decode_error(err: Error) -> ErrorCode {
    match err.code() {
        -25291 => ErrorCode::NoStorageAccess(Box::new(err)), // errSecNotAvailable
        -25292 => ErrorCode::NoStorageAccess(Box::new(err)), // errSecReadOnly
        -25294 => ErrorCode::NoStorageAccess(Box::new(err)), // errSecNoSuchKeychain
        -25295 => ErrorCode::NoStorageAccess(Box::new(err)), // errSecInvalidKeychain
        -25300 => ErrorCode::NoEntry,                        // errSecItemNotFound
        _ => ErrorCode::PlatformFailure(Box::new(err)),
    }
}

#[cfg(test)]
mod tests {
    use super::MacCredential;
    use crate::{tests::generate_random_string, Credential, Entry, Error};

    fn entry_new(service: &str, user: &str) -> Entry {
        match MacCredential::new_with_target(None, service, user) {
            Ok(credential) => {
                let credential: Box<Credential> = Box::new(credential);
                Entry::new_with_credential(credential)
            }
            Err(err) => {
                panic!("Couldn't create entry (service: {service}, user: {user}): {err:?}")
            }
        }
    }

    #[test]
    fn test_invalid_parameter() {
        let credential = MacCredential::new_with_target(None, "", "user");
        assert!(
            matches!(credential, Err(Error::InvalidArgument(_))),
            "Created credential with empty service"
        );
        let credential = MacCredential::new_with_target(None, "service", "");
        assert!(
            matches!(credential, Err(Error::InvalidArgument(_))),
            "Created entry with empty user"
        );
        let credential = MacCredential::new_with_target(Some(""), "service", "user");
        assert!(
            matches!(credential, Err(Error::InvalidArgument(_))),
            "Created entry with empty target"
        );
    }

    #[test]
    fn test_missing_entry() {
        let name = generate_random_string();
        let entry = entry_new(&name, &name);
        assert!(
            matches!(entry.get_password(), Err(Error::NoEntry)),
            "Missing entry has password"
        )
    }

    #[test]
    fn test_empty_password() {
        let name = generate_random_string();
        let entry = entry_new(&name, &name);
        let in_pass = "";
        entry
            .set_password(in_pass)
            .expect("Can't set empty password");
        let out_pass = entry.get_password().expect("Can't get empty password");
        assert_eq!(
            in_pass, out_pass,
            "Retrieved and set empty passwords don't match"
        );
        entry.delete_password().expect("Can't delete password");
        assert!(
            matches!(entry.get_password(), Err(Error::NoEntry)),
            "Able to read a deleted password"
        )
    }

    #[test]
    fn test_round_trip_ascii_password() {
        let name = generate_random_string();
        let entry = entry_new(&name, &name);
        let password = "test ascii password";
        entry
            .set_password(password)
            .expect("Can't set ascii password");
        let stored_password = entry.get_password().expect("Can't get ascii password");
        assert_eq!(
            stored_password, password,
            "Retrieved and set ascii passwords don't match"
        );
        entry
            .delete_password()
            .expect("Can't delete ascii password");
        assert!(
            matches!(entry.get_password(), Err(Error::NoEntry)),
            "Able to read a deleted ascii password"
        )
    }

    #[test]
    fn test_round_trip_non_ascii_password() {
        let name = generate_random_string();
        let entry = entry_new(&name, &name);
        let password = "このきれいな花は桜です";
        entry
            .set_password(password)
            .expect("Can't set non-ascii password");
        let stored_password = entry.get_password().expect("Can't get non-ascii password");
        assert_eq!(
            stored_password, password,
            "Retrieved and set non-ascii passwords don't match"
        );
        entry
            .delete_password()
            .expect("Can't delete non-ascii password");
        assert!(
            matches!(entry.get_password(), Err(Error::NoEntry)),
            "Able to read a deleted non-ascii password"
        )
    }

    #[test]
    fn test_update() {
        let name = generate_random_string();
        let entry = entry_new(&name, &name);
        let password = "test ascii password";
        entry
            .set_password(password)
            .expect("Can't set initial ascii password");
        let stored_password = entry.get_password().expect("Can't get ascii password");
        assert_eq!(
            stored_password, password,
            "Retrieved and set initial ascii passwords don't match"
        );
        let password = "このきれいな花は桜です";
        entry
            .set_password(password)
            .expect("Can't update ascii with non-ascii password");
        let stored_password = entry.get_password().expect("Can't get non-ascii password");
        assert_eq!(
            stored_password, password,
            "Retrieved and updated non-ascii passwords don't match"
        );
        entry
            .delete_password()
            .expect("Can't delete updated password");
        assert!(
            matches!(entry.get_password(), Err(Error::NoEntry)),
            "Able to read a deleted updated password"
        )
    }
}
