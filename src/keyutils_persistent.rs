/*!

# keyutils-persistent credential store

This store is a combination of the [keyutils](crate::keyutils) store
backed up with a persistent [secret-service](crate::secret_service)
store.

 */

use log::debug;

use super::credential::{
    Credential, CredentialApi, CredentialBuilder, CredentialBuilderApi, CredentialPersistence,
};
use super::error::{Error, Result};
use super::keyutils::KeyutilsCredential;
use super::secret_service::SsCredential;

/// Representation of a keyutils-persistent credential.
///
/// The credential owns a [KeyutilsCredential] for in-memory usage and
/// a [SsCredential] for persistence.
#[derive(Debug, Clone)]
pub struct KeyutilsPersistentCredential {
    keyutils: KeyutilsCredential,
    ss: SsCredential,
}

impl CredentialApi for KeyutilsPersistentCredential {
    /// Set a password in the underlying store
    fn set_password(&self, password: &str) -> Result<()> {
        self.set_secret(password.as_bytes())
    }

    /// Set a secret in the underlying store
    ///
    /// It sets first the secret in keyutils, then in
    /// secret-service. If the late one fails, keyutils secret change
    /// is reverted.
    fn set_secret(&self, secret: &[u8]) -> Result<()> {
        let prev_secret = self.keyutils.get_secret();
        self.keyutils.set_secret(secret)?;

        if let Err(err) = self.ss.set_secret(secret) {
            match prev_secret {
                Ok(ref secret) => self.keyutils.set_secret(secret),
                Err(Error::NoEntry) => self.keyutils.delete_credential(),
                Err(err) => Err(err),
            }?;

            return Err(err);
        }

        Ok(())
    }

    /// Retrieve a password from the underlying store
    ///
    /// The password is retrieved from keyutils. In case of error, the
    /// password is retrieved from secret-service instead (and
    /// keyutils is updated).
    fn get_password(&self) -> Result<String> {
        match self.keyutils.get_password() {
            Ok(password) => {
                return Ok(password);
            }
            Err(err) => {
                debug!("cannot get password from keyutils: {err}, trying from secret service")
            }
        }

        let password = self.ss.get_password().map_err(ambigous_to_no_entry)?;
        self.keyutils.set_password(&password)?;

        Ok(password)
    }

    /// Retrieve a secret from the underlying store
    ///
    /// The secret is retrieved from keyutils. In case of error, the
    /// secret is retrieved from secret-service instead (and keyutils
    /// is updated).
    fn get_secret(&self) -> Result<Vec<u8>> {
        match self.keyutils.get_secret() {
            Ok(secret) => {
                return Ok(secret);
            }
            Err(err) => {
                debug!("cannot get secret from keyutils: {err}, trying from secret service")
            }
        }

        let secret = self.ss.get_secret().map_err(ambigous_to_no_entry)?;
        self.keyutils.set_secret(&secret)?;

        Ok(secret)
    }

    /// Delete a password from the underlying store.
    ///
    /// The credential is deleted from both keyutils and
    /// secret-service.
    fn delete_credential(&self) -> Result<()> {
        if let Err(err) = self.keyutils.delete_credential() {
            debug!("cannot delete keyutils credential: {err}");
        }

        self.ss.delete_credential()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl KeyutilsPersistentCredential {
    /// Create the platform credential for a Keyutils entry.
    ///
    /// An explicit target string is interpreted as the KeyRing to use for the entry.
    /// If none is provided, then we concatenate the user and service in the string
    /// `keyring-rs:user@service`.
    pub fn new_with_target(target: Option<&str>, service: &str, user: &str) -> Result<Self> {
        let ss = SsCredential::new_with_target(target, service, user)?;
        let keyutils = KeyutilsCredential::new_with_target(target, service, user)?;
        Ok(Self { keyutils, ss })
    }
}

/// The builder for keyutils-persistent credentials
#[derive(Debug, Default)]
pub struct KeyutilsPersistentCredentialBuilder {}

/// Returns an instance of the keyutils-persistent credential builder.
///
/// If keyutils-persistent is the default credential store, this is
/// called once when an entry is first created.
pub fn default_credential_builder() -> Box<CredentialBuilder> {
    Box::new(KeyutilsPersistentCredentialBuilder {})
}

impl CredentialBuilderApi for KeyutilsPersistentCredentialBuilder {
    /// Build an [KeyutilsPersistentCredential] for the given target, service, and user.
    fn build(&self, target: Option<&str>, service: &str, user: &str) -> Result<Box<Credential>> {
        Ok(Box::new(SsCredential::new_with_target(
            target, service, user,
        )?))
    }

    /// Return the underlying builder object with an `Any` type so that it can
    /// be downgraded to an [KeyutilsPersistentCredentialBuilder] for platform-specific processing.
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    /// This keystore keeps credentials thanks to the inner secret-service store.
    fn persistence(&self) -> CredentialPersistence {
        CredentialPersistence::UntilDelete
    }
}

/// Replace any Ambiguous error with a NoEntry one
fn ambigous_to_no_entry(err: Error) -> Error {
    if let Error::Ambiguous(_) = err {
        return Error::NoEntry;
    };

    err
}

#[cfg(test)]
mod tests {
    use crate::credential::CredentialPersistence;
    use crate::{Entry, Error};

    use super::{default_credential_builder, KeyutilsPersistentCredential};

    #[test]
    fn test_persistence() {
        assert!(matches!(
            default_credential_builder().persistence(),
            CredentialPersistence::UntilDelete
        ))
    }

    fn entry_new(service: &str, user: &str) -> Entry {
        crate::tests::entry_from_constructor(
            KeyutilsPersistentCredential::new_with_target,
            service,
            user,
        )
    }

    #[test]
    fn test_invalid_parameter() {
        let credential = KeyutilsPersistentCredential::new_with_target(Some(""), "service", "user");
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
    fn test_round_trip_random_secret() {
        crate::tests::test_round_trip_random_secret(entry_new);
    }

    #[test]
    fn test_update() {
        crate::tests::test_update(entry_new);
    }

    #[test]
    fn test_noop_get_update_attributes() {
        crate::tests::test_noop_get_update_attributes(entry_new);
    }
}
