/*!

# Linux kernel (keyutils) credential store

Modern linux kernels have a built-in secure store, [keyutils](https://www.man7.org/linux/man-pages/man7/keyutils.7.html).
This module (written primarily by [@landhb](https://github.com/landhb)) uses that secure store
as the persistent back end for entries.

Entries in keyutils are identified by a string `description`.  If an entry is created with
an explicit `target`, that value is used as the keyutils description.  Otherwise, the string
`keyring-rs:user@service` is used (where user and service come from the entry creation call).

A single entry in keyutils can be on multiple "keyrings", each of which has a subtly
different lifetime.  The core storage for keyring keys is provided by the user-specific
[persistent keyring](https://www.man7.org/linux/man-pages/man7/persistent-keyring.7.html),
whose lifetime defaults to a few days (and is controllable by
administrators).  But whenever an entry's credential is used,
it is also added to the user's
[session keyring](https://www.man7.org/linux/man-pages/man7/session-keyring.7.html):
this ensures that the credential will persist as long as the client is running.

## Headless usage

If you are trying to use keyring on a headless linux box, it's strongly recommended that you use this
credential store, because (as part of the kernel) it's designed to be used headlessly.
To set this module as your default store, build with `--features linux-default-keyutils`.
Alternatively, you can drop the secret-service credential store altogether
(which will slim your build significantly) by building keyring
with `--no-default-features` and `--features linux-no-secret-service`.

 */
use super::credential::{Credential, CredentialApi, CredentialBuilder, CredentialBuilderApi};
use super::error::{decode_password, Error as ErrorCode, Result};
use linux_keyutils::{KeyError, KeyRing, KeyRingIdentifier};

/// Representation of a keyutils credential.
///
/// Since the CredentialBuilderApi::build method does not provide
/// an initial secret, and it is impossible to have 0-length keys,
/// this representation holds a linux_keyutils::KeyRing instead
/// of a linux_keyutils::Key.
///
/// The added benefit of this approach
/// is that any call to get_password before set_password is done
/// will result in a proper error as the key does not exist until
/// set_password is called.
#[derive(Debug, Clone)]
pub struct KeyutilsCredential {
    /// Host session keyring
    pub session: KeyRing,
    /// Host persistent keyring
    pub persistent: KeyRing,
    /// Description of the key entry
    pub description: String,
}

impl CredentialApi for KeyutilsCredential {
    /// Set a password in the underlying store
    ///
    /// This will overwrite the entry if it already exists since
    /// it's using `add_key` under the hood.
    ///
    /// Returns an [Invalid](ErrorCode::Invalid) error if the password
    /// is empty, because keyutils keys cannot have empty values.
    fn set_password(&self, password: &str) -> Result<()> {
        if password.is_empty() {
            return Err(ErrorCode::Invalid(
                "password".to_string(),
                "cannot be empty".to_string(),
            ));
        }

        // Add to the session keyring
        let key = self
            .session
            .add_key(&self.description, password)
            .map_err(decode_error)?;

        // Directly link to the persistent keyring as well
        self.persistent.link_key(key).map_err(decode_error)?;
        Ok(())
    }

    /// Retrieve a password from the underlying store
    ///
    /// This requires a call to `Key::read` with checked conversions
    /// to a utf8 Rust string.
    fn get_password(&self) -> Result<String> {
        // Verify that the key exists and is valid
        let key = self
            .session
            .search(&self.description)
            .map_err(decode_error)?;

        // Directly re-link to the session keyring
        // If a logout occurred, it will only be linked to the
        // persistent keyring, and needs to be added again.
        self.session.link_key(key).map_err(decode_error)?;

        // Directly re-link to the persistent keyring
        // If it expired, it will only be linked to the
        // session keyring, and needs to be added again.
        self.persistent.link_key(key).map_err(decode_error)?;

        // Read in the key (making sure we have enough room)
        let buffer = key.read_to_vec().map_err(decode_error)?;

        // Attempt utf-8 conversion
        decode_password(buffer)
    }

    /// Delete a password from the underlying store.
    ///
    /// Under the hood this uses `Key::invalidate` to immediately
    /// invalidate the key and prevent any further successful
    /// searches.
    ///
    /// Note that the keyutils implementation uses caching,
    /// and the caches take some time to clear,
    /// so a key that has been invalidated may still be found
    /// by get_password if it's called within milliseconds
    /// in *the same process* that deleted the key.
    fn delete_password(&self) -> Result<()> {
        // Verify that the key exists and is valid
        let key = self
            .session
            .search(&self.description)
            .map_err(decode_error)?;

        // Invalidate the key immediately
        key.invalidate().map_err(decode_error)?;
        Ok(())
    }

    /// Cast the credential object to std::any::Any.  This allows clients
    /// to downcast the credential to its concrete type so they
    /// can do platform-specific things with it.
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl KeyutilsCredential {
    /// Create a credential from the matching keyutils key.
    ///
    /// This is basically a no-op, because keys don't have extra attributes,
    /// but at least we make sure the underlying platform credential exists.
    pub fn get_credential(&self) -> Result<Self> {
        self.session
            .search(&self.description)
            .map_err(decode_error)?;
        Ok(self.clone())
    }

    /// Create the platform credential for a Keyutils entry.
    ///
    /// An explicit target string is interpreted as the KeyRing to use for the entry.
    /// If none is provided, then we concatenate the user and service in the string
    /// `keyring-rs:user@service`.
    pub fn new_with_target(target: Option<&str>, service: &str, user: &str) -> Result<Self> {
        // Obtain the session keyring
        let session =
            KeyRing::from_special_id(KeyRingIdentifier::Session, false).map_err(decode_error)?;

        // Link the persistent keyring to the session
        let persistent =
            KeyRing::get_persistent(KeyRingIdentifier::Session).map_err(decode_error)?;

        // Construct the credential with a URI-style description
        let description = match target {
            Some(value) if value.is_empty() => {
                return Err(ErrorCode::Invalid(
                    "target".to_string(),
                    "cannot be empty".to_string(),
                ));
            }
            Some(value) => value.to_string(),
            None => format!("keyring-rs:{user}@{service}"),
        };
        Ok(Self {
            session,
            persistent,
            description,
        })
    }
}

/// The builder for keyutils credentials
#[derive(Debug, Copy, Clone)]
struct KeyutilsCredentialBuilder {}

/// Return a keyutils credential builder.
///
/// If features are set to make keyutils the default store,
/// this will be automatically be called once before the
/// first credential is created.
pub fn default_credential_builder() -> Box<CredentialBuilder> {
    Box::new(KeyutilsCredentialBuilder {})
}

impl CredentialBuilderApi for KeyutilsCredentialBuilder {
    /// Build a keyutils credential with the given target, service, and user.
    ///
    /// Building a credential does not create a key in the store.
    /// It's setting a password that does that.
    fn build(&self, target: Option<&str>, service: &str, user: &str) -> Result<Box<Credential>> {
        Ok(Box::new(KeyutilsCredential::new_with_target(
            target, service, user,
        )?))
    }

    /// Return an [Any](std::any::Any) reference to the credential builder.
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Map an underlying keyutils error to a platform-independent error with annotation.
pub fn decode_error(err: KeyError) -> ErrorCode {
    match err {
        // Experimentation has shown that the keyutils implementation can return a lot of
        // different errors that all mean "no such key", depending on where in the invalidation
        // processing the [get_password](KeyutilsCredential::get_password) call is made.
        KeyError::KeyDoesNotExist
        | KeyError::AccessDenied
        | KeyError::KeyRevoked
        | KeyError::KeyExpired => ErrorCode::NoEntry,
        KeyError::InvalidDescription => ErrorCode::Invalid(
            "description".to_string(),
            "rejected by platform".to_string(),
        ),
        KeyError::InvalidArguments => {
            ErrorCode::Invalid("password".to_string(), "rejected by platform".to_string())
        }
        other => ErrorCode::PlatformFailure(wrap(other)),
    }
}

fn wrap(err: KeyError) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(err)
}

#[cfg(test)]
mod tests {
    use crate::{tests::generate_random_string, Entry, Error};

    use super::KeyutilsCredential;

    fn entry_new(service: &str, user: &str) -> Entry {
        crate::tests::entry_from_constructor(KeyutilsCredential::new_with_target, service, user)
    }

    #[test]
    fn test_invalid_parameter() {
        let credential = KeyutilsCredential::new_with_target(Some(""), "service", "user");
        assert!(
            matches!(credential, Err(Error::Invalid(_, _))),
            "Created entry with empty target"
        );
    }

    #[test]
    fn test_empty_service_and_user() {
        crate::tests::test_empty_service_and_user(entry_new);
    }

    #[test]
    fn test_missing_entry() {
        crate::tests::test_missing_entry(entry_new);
    }

    #[test]
    fn test_empty_password() {
        let entry = entry_new("empty password service", "empty password user");
        assert!(
            matches!(entry.set_password(""), Err(Error::Invalid(_, _))),
            "Able to set empty password"
        );
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
        let credential: &KeyutilsCredential = entry
            .get_credential()
            .downcast_ref()
            .expect("Not a Keyutils credential");
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
