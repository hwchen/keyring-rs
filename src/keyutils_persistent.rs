/*!

# keyutils-persistent credential store

TODO

 */
use super::credential::{
    Credential, CredentialApi, CredentialBuilder, CredentialBuilderApi, CredentialPersistence,
};
use super::error::{Error, Result};
use super::keyutils::KeyutilsCredential;
use super::secret_service::SsCredential;

#[derive(Debug, Clone)]
pub struct KeyutilsPersistentCredential {
    keyutils: KeyutilsCredential,
    ss: SsCredential,
}

impl CredentialApi for KeyutilsPersistentCredential {
    fn set_password(&self, password: &str) -> Result<()> {
        self.set_secret(password.as_bytes())
    }

    fn set_secret(&self, secret: &[u8]) -> Result<()> {
        let prev_secret = self.keyutils.get_secret()?;
        self.keyutils.set_secret(secret)?;

        if let Err(err) = self.ss.set_secret(secret) {
            self.keyutils.set_secret(&prev_secret)?;
            return Err(err);
        }

        Ok(())
    }

    fn get_password(&self) -> Result<String> {
        if let Ok(password) = self.keyutils.get_password() {
            return Ok(password);
        }

        let password = self.ss.get_password().map_err(ambigous_to_no_entry)?;
        self.keyutils.set_password(&password)?;

        Ok(password)
    }

    fn get_secret(&self) -> Result<Vec<u8>> {
        if let Ok(secret) = self.keyutils.get_secret() {
            return Ok(secret);
        }

        let secret = self.ss.get_secret().map_err(ambigous_to_no_entry)?;
        self.keyutils.set_secret(&secret)?;

        Ok(secret)
    }

    fn delete_credential(&self) -> Result<()> {
        // TODO: log the error
        let _ = self.keyutils.delete_credential();
        self.ss.delete_credential()?;
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl KeyutilsPersistentCredential {
    pub fn new_with_target(target: Option<&str>, service: &str, user: &str) -> Result<Self> {
        let ss = SsCredential::new_with_target(target, service, user)?;
        let keyutils = KeyutilsCredential::new_with_target(target, service, user)?;
        Ok(Self { keyutils, ss })
    }
}

/// The builder for secret-service-with-keyutils credentials
#[derive(Debug, Default)]
pub struct KeyutilsPersistentCredentialBuilder {}

/// Returns an instance of the secret-service-with-keyutils credential builder.
///
/// If secret-service-with-keyutils is the default credential store,
/// this is called once when an entry is first created.
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

    /// Since this keystore keeps credentials in kernel memory,
    /// they vanish on reboot
    fn persistence(&self) -> CredentialPersistence {
        CredentialPersistence::UntilDelete
    }
}

fn ambigous_to_no_entry(err: Error) -> Error {
    if let Error::Ambiguous(_) = err {
        return Error::NoEntry;
    };

    err
}
