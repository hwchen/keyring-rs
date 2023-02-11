use std::collections::HashMap;

use secret_service::blocking::{Collection, Item, SecretService};
pub use secret_service::{EncryptionType, Error};

use super::credential::{Credential, CredentialApi, CredentialBuilder, CredentialBuilderApi};
use super::error::{decode_password, Error as ErrorCode, Result};

/// Linux supports multiple credential stores, each named by a string.
/// Credentials in a store are identified by an arbitrary collection
/// of attributes, and each can have "label" metadata for use in
/// graphical editors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsCredential {
    pub attributes: HashMap<String, String>,
    pub label: String,
    target: Option<String>,
}

impl CredentialApi for SsCredential {
    fn set_password(&self, password: &str) -> Result<()> {
        let ss = SecretService::connect(EncryptionType::Dh).map_err(platform_failure)?;
        let set_password = |item: &Item| -> Result<()> {
            item.set_secret(password.as_bytes(), "text/plain")
                .map_err(decode_error)
        };
        match self.map_matching_items(set_password, true) {
            Ok(_) => return Ok(()),
            Err(ErrorCode::NoEntry) => {}
            Err(err) => return Err(err),
        }
        let name = self.target.as_ref().ok_or_else(empty_target)?;
        let collection = get_collection(&ss, name).or_else(|_| create_collection(&ss, name))?;
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
        let passwords: Vec<String> = self.map_matching_items(get_item_password, true)?;
        Ok(passwords[0].clone())
    }

    fn delete_password(&self) -> Result<()> {
        self.map_matching_items(delete_item, true)?;
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl SsCredential {
    /// Create a credential for the given target, service, and user.
    pub fn new_with_target(target: Option<&str>, service: &str, user: &str) -> Result<Self> {
        if let Some("") = target {
            return Err(empty_target());
        }
        let target = target.unwrap_or("default");
        let attributes = HashMap::from([
            ("service".to_string(), service.to_string()),
            ("username".to_string(), user.to_string()),
            ("target".to_string(), target.to_string()),
            ("application".to_string(), "rust-keyring".to_string()),
        ]);
        Ok(Self {
            attributes,
            label: format!(
                "keyring-rs v{} for target '{target}', service '{service}', user '{user}'",
                env!("CARGO_PKG_VERSION"),
            ),
            target: Some(target.to_string()),
        })
    }

    // Create a credential from an underlying item that matches it
    fn new_from_item(item: &Item) -> Result<Self> {
        let attributes = item.get_attributes().map_err(decode_error)?;
        let target = attributes.get("target").cloned();
        Ok(Self {
            attributes,
            label: item.get_label().map_err(decode_error)?,
            target,
        })
    }

    /// Construct a credential from the underlying Item, if there is exactly one.
    pub fn get_credential(&self) -> Result<Self> {
        let credentials = self.map_matching_items(Self::new_from_item, true)?;
        Ok(credentials[0].clone())
    }

    /// If there are multiple matching Items, get all of their passwords.
    /// (This is useful if get_password returns an `Ambiguous` error.)
    pub fn get_all_passwords(&self) -> Result<Vec<String>> {
        self.map_matching_items(get_item_password, true)
    }

    /// If there are multiple matching Items, delete all of them.
    /// (This is useful if get_password returns an `Ambiguous` error.)
    pub fn delete_all_passwords(&self) -> Result<()> {
        self.map_matching_items(delete_item, true)?;
        Ok(())
    }

    /// Map a function over all of the items matching this credential.
    /// Items are unlocked before the function is applied.
    /// If `require_unique` is true, and there are no matching items, then
    /// a `NoEntry` error is returned.
    /// If `require_unique` is true, and there is more than one matching item,
    /// then an `Ambiguous` error is returned with a vector of matching credentials.
    fn map_matching_items<F, T>(&self, f: F, require_unique: bool) -> Result<Vec<T>>
    where
        F: Fn(&Item) -> Result<T>,
        T: Sized,
    {
        let ss = SecretService::connect(EncryptionType::Dh).map_err(platform_failure)?;
        let attributes: HashMap<&str, &str> = self.search_attributes().into_iter().collect();
        let search = ss.search_items(attributes).map_err(decode_error)?;
        let target = self.target.as_ref().ok_or_else(empty_target)?;
        let unlocked = matching_items(&search.unlocked, target)?;
        let locked = matching_items(&search.locked, target)?;
        if require_unique {
            let count = locked.len() + unlocked.len();
            if count == 0 {
                return Err(ErrorCode::NoEntry);
            } else if count > 1 {
                let mut creds: Vec<Box<Credential>> = vec![];
                for item in locked.into_iter().chain(unlocked.into_iter()) {
                    let cred = Self::new_from_item(item)?;
                    creds.push(Box::new(cred))
                }
                return Err(ErrorCode::Ambiguous(creds));
            }
        }
        let mut results: Vec<T> = vec![];
        for item in unlocked.into_iter() {
            results.push(f(item)?);
        }
        for item in locked.into_iter() {
            item.unlock().map_err(decode_error)?;
            results.push(f(item)?);
        }
        Ok(results)
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
        result
    }
}

#[derive(Debug, Default)]
pub struct SsCredentialBuilder {}

pub fn default_credential_builder() -> Box<CredentialBuilder> {
    Box::new(SsCredentialBuilder {})
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

//
// Secret Service utilities
//
/// Find the secret service collection that should contain this item
fn get_collection<'a>(ss: &'a SecretService, name: &str) -> Result<Collection<'a>> {
    let collection = ss.get_collection_by_alias(name).map_err(decode_error)?;
    if collection.is_locked().map_err(decode_error)? {
        collection.unlock().map_err(decode_error)?;
    }
    Ok(collection)
}

/// Create the secret service collection that will contain this credential
fn create_collection<'a>(ss: &'a SecretService, name: &str) -> Result<Collection<'a>> {
    let collection = ss
        .create_collection("keyring collection '{name}'", name)
        .map_err(decode_error)?;
    Ok(collection)
}

fn get_item_password(item: &Item) -> Result<String> {
    let bytes = item.get_secret().map_err(decode_error)?;
    decode_password(bytes)
}

fn delete_item(item: &Item) -> Result<()> {
    item.delete().map_err(decode_error)
}

fn matching_items<'a>(source: &'a [Item<'a>], target: &str) -> Result<Vec<&'a Item<'a>>> {
    let mut result: Vec<&'a Item<'a>> = vec![];
    for i in source.iter() {
        match i.get_attributes().map_err(decode_error)?.get("target") {
            None => result.push(i),
            Some(item_target) if target.eq(item_target) => result.push(i),
            _ => {}
        }
    }
    Ok(result)
}

//
// Error utilities
//
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

fn empty_target() -> ErrorCode {
    ErrorCode::Invalid("target".to_string(), "cannot be empty".to_string())
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
            .expect("Not a secret service credential");
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

    fn delete_collection(name: &str) {
        use secret_service::blocking::SecretService;
        pub use secret_service::EncryptionType;

        let ss =
            SecretService::connect(EncryptionType::Dh).expect("Can't connect to secret service");
        let collection = ss
            .get_collection_by_alias(name)
            .expect("Can't find collection to delete");
        collection.delete().expect("Can't delete collection");
    }

    #[test]
    fn test_create_new_target_collection() {
        let name = generate_random_string();
        let credential = SsCredential::new_with_target(Some(&name), &name, &name)
            .expect("Can't create new collection for credential");
        let entry = Entry::new_with_credential(Box::new(credential));
        let password = "password in new collection";
        entry
            .set_password(password)
            .expect("Can't set password for new collection entry");
        let actual = entry
            .get_password()
            .expect("Can't get password for new collection entry");
        assert_eq!(actual, password);
        entry
            .delete_password()
            .expect("Couldn't delete password for new collection entry");
        assert!(matches!(entry.get_password(), Err(Error::NoEntry)));
        delete_collection(&name);
    }

    #[test]
    fn test_separate_targets_dont_interfere() {
        let name1 = generate_random_string();
        let name2 = generate_random_string();
        let credential1 = SsCredential::new_with_target(Some(&name1), &name1, &name1)
            .expect("Can't create new collection for credential1");
        let entry1 = Entry::new_with_credential(Box::new(credential1));
        let credential2 = SsCredential::new_with_target(Some(&name2), &name1, &name1)
            .expect("Can't create new collection for credential2");
        let entry2 = Entry::new_with_credential(Box::new(credential2));
        let entry3 = Entry::new(&name1, &name1).expect("Can't create entry in default collection");
        let password1 = "password for collection 1";
        let password2 = "password for collection 2";
        let password3 = "password for default collection";
        entry1
            .set_password(password1)
            .expect("Can't set password for collection 1");
        entry2
            .set_password(password2)
            .expect("Can't set password for collection 2");
        entry3
            .set_password(password3)
            .expect("Can't set password for default collection");
        let actual1 = entry1
            .get_password()
            .expect("Can't get password for collection 1");
        assert_eq!(actual1, password1);
        let actual2 = entry2
            .get_password()
            .expect("Can't get password for collection 2");
        assert_eq!(actual2, password2);
        let actual3 = entry3
            .get_password()
            .expect("Can't get password for default collection");
        assert_eq!(actual3, password3);
        entry1
            .delete_password()
            .expect("Couldn't delete password for collection 1");
        assert!(matches!(entry1.get_password(), Err(Error::NoEntry)));
        entry2
            .delete_password()
            .expect("Couldn't delete password for collection 2");
        assert!(matches!(entry2.get_password(), Err(Error::NoEntry)));
        entry3
            .delete_password()
            .expect("Couldn't delete password for default collection");
        assert!(matches!(entry3.get_password(), Err(Error::NoEntry)));
        delete_collection(&name1);
        delete_collection(&name2);
    }
}
