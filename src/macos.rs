/*!

# macOS Keychain credential store

macOS credential stores are called keychains.
The OS automatically creates three of them (or four if removable media is being used).
Generic credentials on macOS can be identified by a large number of _key/value_ attributes;
this module (currently) uses only the _account_ and _name_ attributes.

For a given service/username pair,
this module targets a generic credential in the User (login) keychain
whose _account_ is the username and and whose _name_ is the service.
Because of a quirk in the Mac keychain services API, neither the _account_
nor the _name_ may be the empty string. (Empty strings are treated as
wildcards when looking up credentials by attribute value.)

In the _Keychain Access_ UI on Mac, generic credentials created by this module
show up in the passwords area (with their _where_ field equal to their _name_).
_Note_ entries on Mac are also generic credentials and notes created by third-party
applications can be accessed by this module
if you know their _account_ value (not displayed by _Keychain Access_). But
because the difference between a password and a note is platform-dependent,
there's no way to _create_ a note in this module.

You can specify targeting a different keychain by passing the keychain's (case-insensitive)
name as the target parameter to `Entry::new_with_target`.
Any name other than one of the OS-supplied keychains (User, Common, System, and Dynamic)
will be mapped to `User`.
 */
use security_framework::base::Error;
use security_framework::os::macos::keychain::{SecKeychain, SecPreferencesDomain};
use security_framework::os::macos::passwords::find_generic_password;

use super::credential::{Credential, CredentialApi, CredentialBuilder, CredentialBuilderApi};
use super::error::{decode_password, Error as ErrorCode, Result};

/// The representation of a generic Keychain credential.
///
/// The actual credentials can have lots of attributes
/// not represented here.  There's no way to use this
/// module to get at those attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacCredential {
    pub domain: MacKeychainDomain,
    pub service: String,
    pub account: String,
}

impl CredentialApi for MacCredential {
    /// Create and write a credential with password for this entry.
    ///
    /// The new credential replaces any existing one in the store.
    /// Since there is only one credential with a given _account_ and _user_
    /// in any given keychain, there is no chance of ambiguity.
    fn set_password(&self, password: &str) -> Result<()> {
        get_keychain(self)?
            .set_generic_password(&self.service, &self.account, password.as_bytes())
            .map_err(decode_error)?;
        Ok(())
    }

    /// Look up the password for this entry, if any.
    ///
    /// Returns a [NoEntry](ErrorCode::NoEntry) error if there is no
    /// credential in the store.
    fn get_password(&self) -> Result<String> {
        let (password_bytes, _) =
            find_generic_password(Some(&[get_keychain(self)?]), &self.service, &self.account)
                .map_err(decode_error)?;
        decode_password(password_bytes.to_vec())
    }

    /// Delete the underlying generic credential for this entry, if any.
    ///
    /// Returns a [NoEntry](ErrorCode::NoEntry) error if there is no
    /// credential in the store.
    fn delete_password(&self) -> Result<()> {
        let (_, item) =
            find_generic_password(Some(&[get_keychain(self)?]), &self.service, &self.account)
                .map_err(decode_error)?;
        item.delete();
        Ok(())
    }

    /// Return the underlying concrete object with an `Any` type so that it can
    /// be downgraded to a [MacCredential] for platform-specific processing.
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl MacCredential {
    /// Construct a credential from the underlying generic credential.
    ///
    /// On Mac, this is basically a no-op, because we represent any attributes
    /// other than the ones we use to find the generic credential.
    /// But at least this checks whether the underlying credential exists.
    pub fn get_credential(&self) -> Result<Self> {
        let (_, _) =
            find_generic_password(Some(&[get_keychain(self)?]), &self.service, &self.account)
                .map_err(decode_error)?;
        Ok(self.clone())
    }

    /// Create a credential representing a Mac keychain entry.
    ///
    /// A target string is interpreted as the keychain to use for the entry.
    ///
    /// Creating a credential does not put anything into the keychain.
    /// The keychain entry will be created
    /// when [set_password](MacCredential::set_password) is
    /// called.
    ///
    /// This will fail if the service or user strings are empty,
    /// because empty attribute values act as wildcards in the
    /// Keychain Services API.
    pub fn new_with_target(target: Option<&str>, service: &str, user: &str) -> Result<Self> {
        if service.is_empty() {
            return Err(ErrorCode::Invalid(
                "service".to_string(),
                "cannot be empty".to_string(),
            ));
        }
        if user.is_empty() {
            return Err(ErrorCode::Invalid(
                "user".to_string(),
                "cannot be empty".to_string(),
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

/// The builder for Mac keychain credentials
pub struct MacCredentialBuilder {}

/// Returns an instance of the Mac credential builder.
///
/// On Mac,
/// this is called once when an entry is first created.
pub fn default_credential_builder() -> Box<CredentialBuilder> {
    Box::new(MacCredentialBuilder {})
}

impl CredentialBuilderApi for MacCredentialBuilder {
    /// Build a [MacCredential] for the given target, service, and user.
    fn build(&self, target: Option<&str>, service: &str, user: &str) -> Result<Box<Credential>> {
        Ok(Box::new(MacCredential::new_with_target(
            target, service, user,
        )?))
    }

    /// Return the underlying builder object with an `Any` type so that it can
    /// be downgraded to a [MacCredentialBuilder] for platform-specific processing.
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// The four pre-defined Mac keychains.
pub enum MacKeychainDomain {
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

    /// Convert a target specification string to a keychain domain.
    ///
    /// We accept any case in the string,
    /// but the value has to match a known keychain domain name
    /// or else we assume the login keychain is meant.
    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "user" => Ok(MacKeychainDomain::User),
            "system" => Ok(MacKeychainDomain::System),
            "common" => Ok(MacKeychainDomain::Common),
            "dynamic" => Ok(MacKeychainDomain::Dynamic),
            _ => Err(ErrorCode::Invalid(
                "target".to_string(),
                format!("'{s}' is not User, System, Common, or Dynamic"),
            )),
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

/// Map a Mac API error to a crate error with appropriate annotation
///
/// The MacOS error code values used here are from
/// [this reference](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-78/lib/SecBase.h.auto.html)
pub fn decode_error(err: Error) -> ErrorCode {
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
    use crate::{tests::generate_random_string, Entry, Error};

    use super::MacCredential;

    fn entry_new(service: &str, user: &str) -> Entry {
        crate::tests::entry_from_constructor(MacCredential::new_with_target, service, user)
    }

    #[test]
    fn test_invalid_parameter() {
        let credential = MacCredential::new_with_target(None, "", "user");
        assert!(
            matches!(credential, Err(Error::Invalid(_, _))),
            "Created credential with empty service"
        );
        let credential = MacCredential::new_with_target(None, "service", "");
        assert!(
            matches!(credential, Err(Error::Invalid(_, _))),
            "Created entry with empty user"
        );
        let credential = MacCredential::new_with_target(Some(""), "service", "user");
        assert!(
            matches!(credential, Err(Error::Invalid(_, _))),
            "Created entry with empty target"
        );
    }

    #[test]
    fn test_missing_entry() {
        crate::tests::test_missing_entry(entry_new);
    }

    #[test]
    fn test_empty_password() {
        crate::tests::test_empty_password(entry_new);
    }

    #[test]
    fn test_round_trip_ascii_password() {
        crate::tests::test_round_trip_ascii_password(entry_new);
    }

    #[test]
    fn test_round_trip_non_ascii_password() {
        crate::tests::test_round_trip_non_ascii_password(entry_new);
    }

    #[test]
    fn test_update() {
        crate::tests::test_update(entry_new);
    }

    #[test]
    fn test_get_credential() {
        let name = generate_random_string();
        let entry = entry_new(&name, &name);
        let credential: &MacCredential = entry
            .get_credential()
            .downcast_ref()
            .expect("Not a mac credential");
        assert!(
            credential.get_credential().is_err(),
            "Platform credential shouldn't exist yet!"
        );
        entry
            .set_password("test get_credential")
            .expect("Can't set password for get_credential");
        assert!(credential.get_credential().is_ok());
        entry
            .delete_password()
            .expect("Couldn't delete after get_credential");
        assert!(matches!(entry.get_password(), Err(Error::NoEntry)));
    }
}
