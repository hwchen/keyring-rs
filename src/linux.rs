use std::collections::HashMap;

pub use secret_service::Error;
use secret_service::{Collection, EncryptionType, SecretService};

use super::credential::{Credential, CredentialApi, CredentialBuilder, CredentialBuilderApi};
use super::error::{decode_password, Error as ErrorCode, Result};

/// Linux supports multiple credential stores, each named by a string.
/// Credentials in a store are identified by an arbitrary collection
/// of attributes, and each can have "label" metadata for use in
/// graphical editors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxCredential {
    pub collection: String,
    pub attributes: HashMap<String, String>,
    pub label: String,
}

impl CredentialApi for LinuxCredential {
    fn set_password(&self, password: &str) -> Result<()> {
        let ss = SecretService::new(EncryptionType::Dh).map_err(platform_failure)?;
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
        let ss = SecretService::new(EncryptionType::Dh).map_err(decode_error)?;
        let collection = self.get_collection(&ss)?;
        let search = collection
            .search_items(self.attributes())
            .map_err(decode_error)?;
        let item = search.get(0).ok_or(ErrorCode::NoEntry)?;
        let bytes = item.get_secret().map_err(decode_error)?;
        decode_password(bytes)
    }

    fn delete_password(&self) -> Result<()> {
        let ss = SecretService::new(EncryptionType::Dh).map_err(decode_error)?;
        let collection = self.get_collection(&ss)?;
        let search = collection
            .search_items(self.attributes())
            .map_err(decode_error)?;
        let item = search.get(0).ok_or(ErrorCode::NoEntry)?;
        item.delete().map_err(decode_error)?;
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl LinuxCredential {
    /// Read the label on the underlying credential
    pub fn get_credential(&self) -> Result<Self> {
        let mut result = self.clone();
        let ss = SecretService::new(EncryptionType::Dh).map_err(decode_error)?;
        let collection = self.get_collection(&ss)?;
        let search = collection
            .search_items(self.attributes())
            .map_err(decode_error)?;
        let item = search.get(0).ok_or(ErrorCode::NoEntry)?;
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

pub struct LinuxCredentialBuilder {}

pub fn default_credential_builder() -> Box<CredentialBuilder> {
    Box::new(LinuxCredentialBuilder {})
}

impl CredentialBuilderApi for LinuxCredentialBuilder {
    fn build(&self, target: Option<&str>, service: &str, user: &str) -> Result<Box<Credential>> {
        Ok(Box::new(LinuxCredential::new_with_target(
            target, service, user,
        )?))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

fn decode_error(err: Error) -> ErrorCode {
    match err {
        Error::Crypto(_) => platform_failure(err),
        Error::Zbus(_) => platform_failure(err),
        Error::ZbusMsg(_) => platform_failure(err),
        Error::ZbusFdo(_) => platform_failure(err),
        Error::Zvariant(_) => platform_failure(err),
        Error::Locked => no_access(err),
        Error::NoResult => no_access(err),
        Error::Parse => platform_failure(err),
        Error::Prompt => no_access(err),
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
    use crate::{tests::generate_random_string, Credential, Entry, Error};

    use super::LinuxCredential;

    fn entry_new(service: &str, user: &str) -> Entry {
        match LinuxCredential::new_with_target(None, service, user) {
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
        let credential = LinuxCredential::new_with_target(Some(""), "service", "user");
        assert!(
            matches!(credential, Err(Error::Invalid(_, _))),
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

    #[test]
    fn test_get_credential() {
        let name = generate_random_string();
        let entry = entry_new(&name, &name);
        let password = "test get password";
        entry
            .set_password(password)
            .expect("Can't set test get password");
        let credential: &LinuxCredential = entry
            .inner
            .as_any()
            .downcast_ref()
            .expect("Not a linux credential");
        let actual = credential.get_credential().expect("Can't read credential");
        assert_eq!(actual.label, credential.label, "Labels don't match");
        assert_eq!(
            actual.attributes, credential.attributes,
            "Attributes don't match"
        )
    }
}
