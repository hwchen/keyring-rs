use std::collections::HashMap;

// TODO: change to blocking for v3
use secret_service::{Collection, Item, SecretService};
// use secret_service::blocking::{Collection, Item, SecretService};
pub use secret_service::{EncryptionType, Error};

use super::credential::{Credential, CredentialApi, CredentialBuilder, CredentialBuilderApi};
use super::error::{decode_password, Error as ErrorCode, Result};

/// Linux supports multiple credential stores, each named by a string.
/// Credentials in a store are identified by an arbitrary collection
/// of attributes, and each can have "label" metadata for use in
/// graphical editors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsCredential {
    pub search_all: bool,
    pub collection: String,
    pub attributes: HashMap<String, String>,
    pub label: String,
}

impl CredentialApi for SsCredential {
    fn set_password(&self, password: &str) -> Result<()> {
        // TODO: change to connect for v3
        let ss = SecretService::new(EncryptionType::Dh).map_err(platform_failure)?;
        // let ss = SecretService::connect(EncryptionType::Dh).map_err(platform_failure)?;
        let collection = self.get_collection(&ss)?;
        collection
            .create_item(
                self.label.as_str(),
                self.all_attributes(),
                password.as_bytes(),
                true, // replace
                "text/plain",
            )
            .map_err(platform_failure)?;
        Ok(())
    }

    fn get_password(&self) -> Result<String> {
        fn get_password(item: &Item) -> Result<String> {
            let bytes = item.get_secret().map_err(decode_error)?;
            decode_password(bytes)
        }
        self.map_item(get_password)
    }

    fn delete_password(&self) -> Result<()> {
        fn delete_item(item: &Item) -> Result<()> {
            item.delete().map_err(decode_error)
        }
        self.map_item(delete_item)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl SsCredential {
    /// Create a credential for the given entries.
    ///
    /// See the top-level module docs for conventions used.
    pub fn new_with_target(
        search_all: bool,
        target: Option<&str>,
        service: &str,
        user: &str,
    ) -> Result<Self> {
        if let Some("") = target {
            return Err(ErrorCode::Invalid(
                "target".to_string(),
                "cannot be empty".to_string(),
            ));
        }
        let target = target.unwrap_or("default");
        let mut attributes = HashMap::from([
            ("service".to_string(), service.to_string()),
            ("username".to_string(), user.to_string()),
            ("application".to_string(), "rust-keyring".to_string()),
        ]);
        if search_all {
            attributes.insert("target".to_string(), target.to_string());
        }
        Ok(Self {
            search_all,
            collection: target.to_string(),
            attributes,
            label: format!(
                "keyring-rs v{} for target '{}', service '{}', user '{}'",
                env!("CARGO_PKG_VERSION"),
                target,
                service,
                user
            ),
        })
    }

    /// Construct a credential from the underlying platform credential, if there is exactly one.
    pub fn get_credential(&self) -> Result<Self> {
        self.map_item(|i: &Item| self.clone_from_item(i))
    }

    /// Map the matching item for this credential, if there is exactly one.
    fn map_item<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Item) -> Result<T>,
        T: Sized,
    {
        // TODO: change to connect for v3
        let ss = SecretService::new(EncryptionType::Dh).map_err(platform_failure)?;
        // let ss = SecretService::connect(EncryptionType::Dh).map_err(platform_failure)?;
        let map_only_item = |search: &Vec<Item>| -> Result<T> {
            let item = match search.len() {
                0 => return Err(ErrorCode::NoEntry),
                1 => &search[0],
                _ => {
                    let mut creds: Vec<Box<Credential>> = vec![];
                    for item in search.iter() {
                        let cred = self.clone_from_item(item)?;
                        creds.push(Box::new(cred))
                    }
                    return Err(ErrorCode::Ambiguous(creds));
                }
            };
            if item.is_locked().map_err(decode_error)? {
                item.unlock().map_err(decode_error)?;
            }
            f(item)
        };
        if self.search_all {
            // TODO: change to locked/unlocked return val in v3
            let attributes: Vec<(&str, &str)> = self.search_attributes().into_iter().collect();
            let search = ss.search_items(attributes).map_err(decode_error)?;
            map_only_item(&search)
        } else {
            let collection = self.get_collection(&ss)?;
            let search = collection
                .search_items(self.search_attributes())
                .map_err(decode_error)?;
            map_only_item(&search)
        }
    }

    // Create a credential from an underlying item that matches it
    fn clone_from_item(&self, item: &Item) -> Result<Self> {
        let mut result = self.clone();
        result.attributes = item.get_attributes().map_err(decode_error)?;
        result.label = item.get_label().map_err(decode_error)?;
        Ok(result)
    }

    /// Find the secret service collection that will contain this item
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
    fn all_attributes(&self) -> HashMap<&str, &str> {
        self.attributes
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect()
    }

    /// Similar to all_attributes, but this just selects the ones we search on
    fn search_attributes(&self) -> HashMap<&str, &str> {
        let mut result: HashMap<&str, &str> = HashMap::new();
        result.insert("service", self.attributes["service"].as_str());
        result.insert("username", self.attributes["username"].as_str());
        if self.search_all {
            result.insert("target", self.attributes["target"].as_str());
        }
        result
    }
}

#[derive(Debug, Default)]
pub struct SsCredentialBuilder {
    search_all: bool,
}

pub fn default_credential_builder() -> Box<CredentialBuilder> {
    Box::new(SsCredentialBuilder::new_with_options(true))
}

impl CredentialBuilderApi for SsCredentialBuilder {
    fn build(&self, target: Option<&str>, service: &str, user: &str) -> Result<Box<Credential>> {
        Ok(Box::new(SsCredential::new_with_target(
            self.search_all,
            target,
            service,
            user,
        )?))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl SsCredentialBuilder {
    pub fn new_with_options(search_all: bool) -> Self {
        Self { search_all }
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
        // TODO: uncomment for v3
        // Error::Unavailable => platform_failure(err),
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
    use crate::{tests::generate_random_string, Entry, Error, Result};

    use super::SsCredential;

    fn entry_new_false(service: &str, user: &str) -> Entry {
        fn new_false(target: Option<&str>, service: &str, user: &str) -> Result<SsCredential> {
            SsCredential::new_with_target(false, target, service, user)
        }
        crate::tests::entry_from_constructor(new_false, service, user)
    }

    fn entry_new_true(service: &str, user: &str) -> Entry {
        fn new_true(target: Option<&str>, service: &str, user: &str) -> Result<SsCredential> {
            SsCredential::new_with_target(true, target, service, user)
        }
        crate::tests::entry_from_constructor(new_true, service, user)
    }

    #[test]
    fn test_invalid_parameter() {
        let credential = SsCredential::new_with_target(false, Some(""), "service", "user");
        assert!(
            matches!(credential, Err(Error::Invalid(_, _))),
            "Created entry with empty target"
        );
    }

    #[test]
    fn test_empty_service_and_user() {
        crate::tests::test_empty_service_and_user(entry_new_false);
        crate::tests::test_empty_service_and_user(entry_new_true);
    }

    #[test]
    fn test_missing_entry() {
        crate::tests::test_missing_entry(entry_new_false);
        crate::tests::test_missing_entry(entry_new_true);
    }

    #[test]
    fn test_empty_password() {
        crate::tests::test_empty_password(entry_new_false);
        crate::tests::test_empty_password(entry_new_true);
    }

    #[test]
    fn test_round_trip_ascii_password() {
        crate::tests::test_round_trip_ascii_password(entry_new_false);
        crate::tests::test_round_trip_ascii_password(entry_new_true);
    }

    #[test]
    fn test_round_trip_non_ascii_password() {
        crate::tests::test_round_trip_non_ascii_password(entry_new_false);
        crate::tests::test_round_trip_non_ascii_password(entry_new_true);
    }

    #[test]
    fn test_update() {
        crate::tests::test_update(entry_new_false);
        crate::tests::test_update(entry_new_true);
    }

    #[test]
    fn test_get_credential() {
        fn test_get_credential_inner(entry: Entry) {
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
        let name1 = generate_random_string();
        let entry1 = entry_new_false(&name1, &name1);
        test_get_credential_inner(entry1);
        let name2 = generate_random_string();
        let entry2 = entry_new_false(&name2, &name2);
        test_get_credential_inner(entry2);
    }

    #[test]
    fn test_search_collection_finds_and_replaces_search_all() {
        let name = generate_random_string();
        let entry1 = entry_new_false(&name, &name);
        let entry2 = entry_new_true(&name, &name);
        let password1 = "search-collection-finds-all";
        entry2
            .set_password(password1)
            .expect("Can't set s-c-f-a password");
        let found1 = entry1
            .get_password()
            .expect("Search collection doesn't find all");
        assert_eq!(found1, password1, "Collection password doesn't match all");
        let password2 = "set-collection-replaces-existing";
        entry1
            .set_password(password2)
            .expect("Search collection couldn't set password");
        entry2
            .get_password()
            .expect_err("target attribute wasn't replaced!");
        entry2
            .delete_password()
            .expect_err("Delete succeeded on search-all credential");
        entry1
            .delete_password()
            .expect("Delete failed on search-collection credential");
    }

    #[test]
    fn test_search_all_doesnt_find_collection_and_creates_new() {
        let name = generate_random_string();
        let entry1 = entry_new_false(&name, &name);
        let entry2 = entry_new_true(&name, &name);
        let password1 = "search-all-doesn't find collection";
        entry1
            .set_password(password1)
            .expect("Search collection couldn't set password");
        entry2
            .get_password()
            .expect_err("Search all found collection password");
        let password2 = "search-all-creates-new";
        entry2
            .set_password(password2)
            .expect("Search all couldn't set password");
        entry1
            .get_password()
            .expect_err("Search collection found only one password");
        let found = entry2
            .get_password()
            .expect("Search all couldn't get password");
        assert_eq!(found, password2, "Search all found collection password");
        entry2
            .delete_password()
            .expect("Delete failed on search-all credential");
        entry1
            .delete_password()
            .expect("Delete failed on search-collection credential after search-all deleted");
    }
}
