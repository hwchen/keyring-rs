/*!

# secret-service-with-keyutils credential store

TODO

 */
use std::collections::HashMap;

#[cfg(feature = "sync-secret-service")]
use dbus_secret_service::{Error, Item};
#[cfg(feature = "async-secret-service")]
use secret_service::{blocking::Item, Error};

#[cfg(all(target_os = "linux", feature = "linux-native"))]
use crate::keyutils::KeyutilsCredential;
use crate::secret_service::{decode_error, SsCredential};

use super::credential::{Credential, CredentialApi, CredentialBuilder, CredentialBuilderApi};
use super::error::Result;

#[derive(Debug, Clone)]
pub struct SsKeyutilsCredential {
    keyutils: KeyutilsCredential,
    ss: SsCredential,
}

impl CredentialApi for SsKeyutilsCredential {
    fn set_password(&self, password: &str) -> Result<()> {
        self.set_secret(password.as_bytes())
    }

    fn set_secret(&self, secret: &[u8]) -> Result<()> {
        self.ss.set_secret(secret)?;
        let _ = self.keyutils.set_secret(secret);
        Ok(())
    }

    fn get_password(&self) -> Result<String> {
        if let Ok(password) = self.keyutils.get_password() {
            return Ok(password);
        }

        let password = self.ss.get_password()?;
        let _ = self.keyutils.set_password(&password);

        Ok(password)
    }

    fn get_secret(&self) -> Result<Vec<u8>> {
        if let Ok(secret) = self.keyutils.get_secret() {
            return Ok(secret);
        }

        let secret = self.ss.get_secret()?;
        let _ = self.keyutils.set_secret(&secret);

        Ok(secret)
    }

    fn get_attributes(&self) -> Result<HashMap<String, String>> {
        self.ss.get_attributes()
    }

    fn update_attributes(&self, attributes: &HashMap<&str, &str>) -> Result<()> {
        self.ss.update_attributes(attributes)
    }

    fn delete_credential(&self) -> Result<()> {
        self.ss.delete_credential()?;
        let _ = self.keyutils.delete_credential();
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl KeyutilsCredential {
    /// Create a keyutils credential from an underlying secret service
    /// item's attributes.
    ///
    /// The created credential will have all the attributes and label
    /// of the underlying item, so you can examine them.
    pub fn new_from_item(item: &Item) -> Result<KeyutilsCredential> {
        let attributes = item.get_attributes().map_err(decode_error)?;

        let target = attributes.get("target").map(|target| target.as_str());
        let service = attributes
            .get("service")
            .ok_or(decode_error(Error::NoResult))?;
        let user = attributes
            .get("username")
            .ok_or(decode_error(Error::NoResult))?;

        let keyutils = KeyutilsCredential::new_with_target(target, service.as_str(), user.as_str())
            .map_err(|err| crate::Error::NoStorageAccess(Box::new(err)))?;

        Ok(keyutils)
    }
}

impl SsKeyutilsCredential {
    pub fn new_with_target(target: Option<&str>, service: &str, user: &str) -> Result<Self> {
        let ss = SsCredential::new_with_target(target, service, user)?;
        let keyutils = KeyutilsCredential::new_with_target(target, service, user)?;
        Ok(Self { keyutils, ss })
    }

    pub fn new_with_no_target(service: &str, user: &str) -> Result<Self> {
        let keyutils = KeyutilsCredential::new_with_target(None, service, user)?;
        let ss = SsCredential::new_with_no_target(service, user)?;
        Ok(Self { keyutils, ss })
    }

    pub fn new_from_item(item: &Item) -> Result<Self> {
        let ss = SsCredential::new_from_item(item)?;
        let keyutils = KeyutilsCredential::new_from_item(item)?;
        Ok(Self { keyutils, ss })
    }

    pub fn get_all_passwords(&self) -> Result<Vec<String>> {
        self.ss.get_all_passwords()
    }

    pub fn delete_all_passwords(&self) -> Result<()> {
        self.ss.delete_all_passwords()
    }

    pub fn all_attributes(&self) -> HashMap<&str, &str> {
        self.ss.all_attributes()
    }

    pub fn search_attributes(&self, omit_target: bool) -> HashMap<&str, &str> {
        self.ss.search_attributes(omit_target)
    }
}

/// The builder for secret-service-with-keyutils credentials
#[derive(Debug, Default)]
pub struct SsKeyutilsCredentialBuilder {}

/// Returns an instance of the secret-service-with-keyutils credential builder.
///
/// If secret-service-with-keyutils is the default credential store,
/// this is called once when an entry is first created.
pub fn default_credential_builder() -> Box<CredentialBuilder> {
    Box::new(SsKeyutilsCredentialBuilder {})
}

impl CredentialBuilderApi for SsKeyutilsCredentialBuilder {
    /// Build an [SsKeyutilsCredential] for the given target, service, and user.
    fn build(&self, target: Option<&str>, service: &str, user: &str) -> Result<Box<Credential>> {
        Ok(Box::new(SsCredential::new_with_target(
            target, service, user,
        )?))
    }

    /// Return the underlying builder object with an `Any` type so that it can
    /// be downgraded to an [SsKeyutilsCredentialBuilder] for platform-specific processing.
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
