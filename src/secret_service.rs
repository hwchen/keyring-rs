use std::collections::HashMap;

use secret_service::blocking::{Collection, SecretService};
pub use secret_service::{EncryptionType, Error, Item};

use super::credential::{Credential, CredentialApi, CredentialBuilder, CredentialBuilderApi};
use super::error::{decode_password, Error as ErrorCode, Result};

/// Linux supports multiple credential stores, each named by a string.
/// Credentials in a store are identified by an arbitrary collection
/// of attributes, and each can have "label" metadata for use in
/// graphical editors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsCredential {
    pub collection: String,
    pub attributes: HashMap<String, String>,
    pub label: String,
}

impl CredentialApi for SsCredential {
    fn set_password(&self, password: &str) -> Result<()> {
        let ss = SecretService::connect(EncryptionType::Dh).map_err(platform_failure)?;
        let collection = self.get_collection(&ss)?;
        collection
            .create_item(
                self.label.as_str(),
                self.attributes(),
                password.as_bytes(),
                true, // replace
                "text/plain",
            )
            .map_err(platform_failure)?;
        Ok(())
    }

    fn get_password(&self) -> Result<String> {
        let ss = SecretService::connect(EncryptionType::Dh).map_err(decode_error)?;
        let collection = self.get_collection(&ss)?;
        let search = collection
            .search_items(self.attributes())
            .map_err(decode_error)?;
        let item = search.first().ok_or(ErrorCode::NoEntry)?;
        if item.is_locked().map_err(decode_error)? {
            item.unlock().map_err(decode_error)?;
        }
        let bytes = item.get_secret().map_err(decode_error)?;
        decode_password(bytes)
    }

    fn delete_password(&self) -> Result<()> {
        let ss = SecretService::connect(EncryptionType::Dh).map_err(decode_error)?;
        let collection = self.get_collection(&ss)?;
        let search = collection
            .search_items(self.attributes())
            .map_err(decode_error)?;
        let item = search.first().ok_or(ErrorCode::NoEntry)?;
        if item.is_locked().map_err(decode_error)? {
            item.unlock().map_err(decode_error)?;
        }
        item.delete().map_err(decode_error)?;
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl SsCredential {
    /// Construct a credential from the underlying platform credential
    pub fn get_credential(&self) -> Result<Self> {
        let mut result = self.clone();
        let ss = SecretService::connect(EncryptionType::Dh).map_err(decode_error)?;
        let collection = self.get_collection(&ss)?;
        let search = collection
            .search_items(self.attributes())
            .map_err(decode_error)?;
        let item = search.first().ok_or(ErrorCode::NoEntry)?;
        if item.is_locked().map_err(decode_error)? {
            item.unlock().map_err(decode_error)?;
        }
        result.attributes = item.get_attributes().map_err(decode_error)?;
        result.label = item.get_label().map_err(decode_error)?;
        Ok(result)
    }

    /// Find the secret service collection for the map
    fn get_collection<'a>(&self, ss: &'a SecretService) -> Result<Collection<'a>> {
        let collection = ss
            .get_collection_by_alias(self.collection.as_str())
            .map_err(decode_error)?;
        if collection.is_locked().map_err(decode_error)? {
            collection.unlock().map_err(decode_error)?;
        }
        Ok(collection)
    }

    /// Using strings in the credential map makes managing the lifetime
    /// of the credential much easier.  But since the secret service expects
    /// a map from &str to &str, we have this utility to transform the
    /// credential's map into one of the right form.
    fn attributes(&self) -> HashMap<&str, &str> {
        self.attributes
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect()
    }

    /// Create a credential for the given entries.
    ///
    /// See the top-level module docs for conventions used.
    pub fn new_with_target(target: Option<&str>, service: &str, user: &str) -> Result<Self> {
        if let Some("") = target {
            return Err(ErrorCode::Invalid(
                "target".to_string(),
                "cannot be empty".to_string(),
            ));
        }
        let target = target.unwrap_or("default");
        Ok(Self {
            collection: target.to_string(),
            attributes: HashMap::from([
                ("service".to_string(), service.to_string()),
                ("username".to_string(), user.to_string()),
                ("application".to_string(), "rust-keyring".to_string()),
            ]),
            label: format!(
                "keyring-rs v{} for target '{}', service '{}', user '{}'",
                env!("CARGO_PKG_VERSION"),
                target,
                service,
                user
            ),
        })
    }
}

#[derive(Debug)]
pub struct SsCredentialBuilder {
    name: String,
    target: TargetUsage,
    search: SearchType,
}

#[derive(Debug, Clone)]
pub enum TargetUsage {
    CollectionOnly,
    AttributeOnly,
    CollectionAndAttribute,
}

#[derive(Debug, Clone)]
pub enum SearchType {
    Collection,
    Everywhere(TargetAttributeHandling),
}

#[derive(Debug, Clone)]
pub enum TargetAttributeHandling {
    Prefer,
    Require,
    DontCare,
}

pub fn default_credential_builder() -> Box<CredentialBuilder> {
    Box::new(SsCredentialBuilder {
        name: "SsDefault".to_string(),
        target: TargetUsage::CollectionOnly,
        search: SearchType::Collection,
    })
}

impl CredentialBuilderApi for SsCredentialBuilder {
    fn build(&self, target: Option<&str>, service: &str, user: &str) -> Result<Box<Credential>> {
        Ok(Box::new(SsCredential::new_with_target(
            target, service, user,
        )?))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl SsCredentialBuilder {
    pub fn new_with_options(name: &str, target: &TargetUsage, search: &SearchType) -> Self {
        Self {
            name: name.to_string(),
            target: target.clone(),
            search: search.clone(),
        }
    }

    pub fn name(&self) -> String {
        self.name.clone()
    }

    pub fn target(&self) -> TargetUsage {
        self.target.clone()
    }

    pub fn search(&self) -> SearchType {
        self.search.clone()
    }
}

fn decode_error(err: Error) -> ErrorCode {
    match err {
        Error::Crypto(_) => platform_failure(err),
        Error::Zbus(_) => platform_failure(err),
        Error::ZbusFdo(_) => platform_failure(err),
        Error::Zvariant(_) => platform_failure(err),
        Error::Locked => no_access(err),
        Error::NoResult => no_access(err),
        Error::Prompt => no_access(err),
        Error::Unavailable => platform_failure(err),
        _ => platform_failure(err),
    }
}

fn platform_failure(err: Error) -> ErrorCode {
    ErrorCode::PlatformFailure(wrap(err))
}

fn no_access(err: Error) -> ErrorCode {
    ErrorCode::NoStorageAccess(wrap(err))
}

fn wrap(err: Error) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(err)
}

#[cfg(test)]
mod tests {
    use crate::{tests::generate_random_string, Entry, Error};

    use super::SsCredential;

    fn entry_new(service: &str, user: &str) -> Entry {
        crate::tests::entry_from_constructor(SsCredential::new_with_target, service, user)
    }

    #[test]
    fn test_invalid_parameter() {
        let credential = SsCredential::new_with_target(Some(""), "service", "user");
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
        entry
            .set_password("test get credential")
            .expect("Can't set password for get_credential");
        let credential: &SsCredential = entry
            .get_credential()
            .downcast_ref()
            .expect("Not a linux credential");
        let actual = credential.get_credential().expect("Can't read credential");
        assert_eq!(actual.label, credential.label, "Labels don't match");
        for (key, value) in &credential.attributes {
            assert_eq!(
                actual.attributes.get(key).expect("Missing attribute"),
                value,
                "Attribute mismatch"
            )
        }
        entry
            .delete_password()
            .expect("Couldn't delete get-credential");
        assert!(matches!(entry.get_password(), Err(Error::NoEntry)));
    }
}
