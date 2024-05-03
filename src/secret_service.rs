/*!

# secret-service credential store

Items in the secret-service are identified by an arbitrary collection
of attributes, and each has "label" for use in graphical editors.  This
implementation uses the following attributes:

- `target` (optional & taken from entry creation call, defaults to `default`)
- `service` (required & taken from entry creation call)
- `username` (required & taken from entry creation call)
- `application` (optional & always set to `rust-keyring`)

Existing items are always searched for at the service level, which
means all collections are searched.  Only the required attributes are used in searches,
so 3rd party clients (such as v1 of this crate) that use matching service and user fields
will have their items found by our searches.  (Items we write with
the same service and user attributes but different target attributes will also come
back in searches, but they are filtered out of the results automatically.)

New items are always created with all four attributes, and if they have
a non-default target then they are created in a collection whose label matches
the target (creating it if necessary).

Setting the password on an entry will always update the password on an
existing item in preference to creating a new item.
This provides better compatibility with 3rd party clients that may already
have created items that match the entry, and reduces the chance
of ambiguity in later searches.

## Async runtime required

While this crate uses the secret-service via its blocking API,
the secret-service crate is built on zbus which always talks to the dbus via async calls.
Thus, using the secret-service implies using an async runtime under the covers.
If you are already using an async runtime,
you can use keyring features to make sure that secret-service
uses a compatible runtime. But be careful: if you make keyring calls
on the main thread in this situation, you will likely crash because
you will block the main thread (see\
[this issue on GitHub](https://github.com/hwchen/keyring-rs/issues/132)
for details).  You will need to spawn a separate thread on which
you make your keyring calls so the main thread doesn't block.

## Headless usage

If you must use the secret-service on a headless linux box,
be aware that there are known issues with getting
dbus and secret-service and the gnome keyring
to work properly in headless environments.
For a quick workaround, look at how this project's
[CI workflow](https://github.com/hwchen/keyring-rs/blob/master/.github/workflows/build.yaml)
uses the
[linux-test.sh](https://github.com/hwchen/keyring-rs/blob/master/linux-test.sh) script;
a similar solution is also documented in the
[Python Keyring docs](https://pypi.org/project/keyring/)
(search for "Using Keyring on headless Linux systems").
The following `bash` function may be helpful:

```shell
function unlock-keyring ()
{
    read -rsp "Password: " pass
    echo -n "$pass" | gnome-keyring-daemon --unlock
    unset pass
}
```

For an excellent treatment of all the headless dbus issues, see
[this answer on ServerFault](https://serverfault.com/a/906224/79617).

## Usage - not! - on Windows Subsystem for Linux

As noted in
[this issue on GitHub](https://github.com/hwchen/keyring-rs/issues/133),
there is no "default" collection defined under WSL.  So
this keystore doesn't work "out of the box" on WSL.  See the
issue for more details and possible workarounds.
 */
use std::collections::HashMap;

use secret_service::blocking::{Collection, Item, SecretService};
use secret_service::{EncryptionType, Error};

use super::credential::{
    Credential, CredentialApi, CredentialBuilder, CredentialBuilderApi, CredentialSearch,
    CredentialSearchApi, CredentialSearchResult,
};
use super::error::{decode_password, Error as ErrorCode, Result};

/// The representation of an item in the secret-service.
///
/// This structure has two roles. On the one hand, it captures all the
/// information a user specifies for an [Entry](crate::Entry)
/// and so is the basis for our search
/// (or creation) of an item for that entry.  On the other hand, when
/// a search is ambiguous, each item found is represented by a credential that
/// has the same attributes and label as the item.
#[derive(Debug, Clone)]
pub struct SsCredential {
    pub attributes: HashMap<String, String>,
    pub label: String,
    target: Option<String>,
}

impl CredentialApi for SsCredential {
    /// Sets the password on a unique matching item, if it exists, or creates one if necessary.
    ///
    /// If there are multiple matches,
    /// returns an [Ambiguous](ErrorCode::Ambiguous) error with a credential for each
    /// matching item.
    ///
    /// When creating, the item is put into a collection named by the credential's `target`
    /// attribute.  
    fn set_password(&self, password: &str) -> Result<()> {
        let ss = SecretService::connect(EncryptionType::Dh).map_err(platform_failure)?;
        // first try to find a unique, existing, matching item and set its password
        match self.map_matching_items(|i| set_item_password(i, password), true) {
            Ok(_) => return Ok(()),
            Err(ErrorCode::NoEntry) => {}
            Err(err) => return Err(err),
        }
        // if there is no existing item, create one for this credential.  In order to create
        // an item, the credential must have an explicit target.  All entries created with
        // the [new] or [new_with_target] commands will have explicit targets.  But entries
        // created to wrap 3rd-party items that don't have `target` attributes may not.
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

    /// Gets the password on a unique matching item, if it exists.
    ///
    /// If there are no
    /// matching items, returns a [NoEntry](ErrorCode::NoEntry) error.
    /// If there are multiple matches,
    /// returns an [Ambiguous](ErrorCode::Ambiguous)
    /// error with a credential for each matching item.
    fn get_password(&self) -> Result<String> {
        let passwords: Vec<String> = self.map_matching_items(get_item_password, true)?;
        Ok(passwords[0].clone())
    }

    /// Deletes the unique matching item, if it exists.
    ///
    /// If there are no
    /// matching items, returns a [NoEntry](ErrorCode::NoEntry) error.
    /// If there are multiple matches,
    /// returns an [Ambiguous](ErrorCode::Ambiguous)
    /// error with a credential for each matching item.
    fn delete_password(&self) -> Result<()> {
        self.map_matching_items(delete_item, true)?;
        Ok(())
    }

    /// Return the underlying credential object with an `Any` type so that it can
    /// be downgraded to an [SsCredential] for platform-specific processing.
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl SsCredential {
    /// Create a credential for the given target, service, and user.
    ///
    /// The target defaults to `default` (the default secret-service collection).
    ///
    /// Creating this credential does not create a matching item.
    /// If there isn't already one there, it will be created only
    /// when [set_password](SsCredential::set_password) is
    /// called.
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

    /// Create a credential from an underlying item.
    ///
    /// The created credential will have all the attributes and label
    /// of the underlying item, so you can examine them.
    pub fn new_from_item(item: &Item) -> Result<Self> {
        let attributes = item.get_attributes().map_err(decode_error)?;
        let target = attributes.get("target").cloned();
        Ok(Self {
            attributes,
            label: item.get_label().map_err(decode_error)?,
            target,
        })
    }

    /// Construct a credential for this credential's underlying matching item,
    /// if there is exactly one.
    pub fn new_from_matching_item(&self) -> Result<Self> {
        let credentials = self.map_matching_items(Self::new_from_item, true)?;
        Ok(credentials[0].clone())
    }

    /// If there are multiple matching items for this credential, get all of their passwords.
    ///
    /// (This is useful if [get_password](SsCredential::get_password)
    /// returns an [Ambiguous](ErrorCode::Ambiguous) error.)
    pub fn get_all_passwords(&self) -> Result<Vec<String>> {
        self.map_matching_items(get_item_password, true)
    }

    /// If there are multiple matching items for this credential, delete all of them.
    ///
    /// (This is useful if [delete_password](SsCredential::delete_password)
    /// returns an [Ambiguous](ErrorCode::Ambiguous) error.)
    pub fn delete_all_passwords(&self) -> Result<()> {
        self.map_matching_items(delete_item, true)?;
        Ok(())
    }

    /// Map a function over all of the items matching this credential.
    ///
    /// Items are unlocked before the function is applied.
    ///
    /// If `require_unique` is true, and there are no matching items, then
    /// a [NoEntry](ErrorCode::NoEntry) error is returned.
    /// If `require_unique` is true, and there are multiple matches,
    /// then an [Ambiguous](ErrorCode::Ambiguous) error is returned
    /// with a vector containing one
    /// credential for each of the matching items.
    pub fn map_matching_items<F, T>(&self, f: F, require_unique: bool) -> Result<Vec<T>>
    where
        F: Fn(&Item) -> Result<T>,
        T: Sized,
    {
        let ss = SecretService::connect(EncryptionType::Dh).map_err(platform_failure)?;
        let attributes: HashMap<&str, &str> = self.search_attributes().into_iter().collect();
        let search = ss.search_items(attributes).map_err(decode_error)?;
        let target = self.target.as_ref().ok_or_else(empty_target)?;
        let unlocked = matching_target_items(&search.unlocked, target)?;
        let locked = matching_target_items(&search.locked, target)?;
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

    /// Similar to [all_attributes](SsCredential::all_attributes),
    /// but this just selects the ones we search on
    fn search_attributes(&self) -> HashMap<&str, &str> {
        let mut result: HashMap<&str, &str> = HashMap::new();
        result.insert("service", self.attributes["service"].as_str());
        result.insert("username", self.attributes["username"].as_str());
        result
    }
}

/// The builder for secret-service credentials
#[derive(Debug, Default)]
pub struct SsCredentialBuilder {}

/// Returns an instance of the secret-service credential builder.
///
/// If secret-service is the default credential store,
/// this is called once when an entry is first created.
pub fn default_credential_builder() -> Box<CredentialBuilder> {
    Box::new(SsCredentialBuilder {})
}

impl CredentialBuilderApi for SsCredentialBuilder {
    /// Build an [SsCredential] for the given target, service, and user.
    fn build(&self, target: Option<&str>, service: &str, user: &str) -> Result<Box<Credential>> {
        Ok(Box::new(SsCredential::new_with_target(
            target, service, user,
        )?))
    }

    /// Return the underlying builder object with an `Any` type so that it can
    /// be downgraded to an [SsCredentialBuilder] for platform-specific processing.
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

pub struct SsCredentialSearch {}

/// Returns the Secret service default credential search structure.
///
/// This creates a new search structure. The by method has no concrete search types
/// like in Windows, iOS, and MacOS. The keys to these credentials can be whatever the user sets them to
/// and is displayed as a HashMap.
pub fn default_credential_search() -> Box<CredentialSearch> {
    Box::new(SsCredentialSearch {})
}

impl CredentialSearchApi for SsCredentialSearch {
    fn by(&self, by: &str, query: &str) -> CredentialSearchResult {
        search_items(by, query)
    }
}

// Returns the items searched as a CredentialSearchResult
fn search_items(by: &str, query: &str) -> CredentialSearchResult {
    let ss = match SecretService::connect(EncryptionType::Plain) {
        Ok(connection) => connection,
        Err(err) => return Err(ErrorCode::SearchError(err.to_string())),
    };

    let collections = match ss.get_all_collections() {
        Ok(collections) => collections,
        Err(err) => return Err(ErrorCode::SearchError(err.to_string())),
    };

    let mut search_map = HashMap::new();
    search_map.insert(by, query);

    let mut outer_map: HashMap<String, HashMap<String, String>> = HashMap::new();
    for collection in collections {
        let search_results = match collection.search_items(search_map.clone()) {
            Ok(results) => results,
            Err(err) => return Err(ErrorCode::SearchError(err.to_string())),
        };

        for result in search_results {
            let attributes = match result.get_attributes() {
                Ok(attributes) => attributes,
                Err(err) => return Err(ErrorCode::SearchError(err.to_string())),
            };

            let mut inner_map: HashMap<String, String> = HashMap::new();

            for (key, value) in attributes {
                inner_map.insert(key, value);

                let label = match result.get_label() {
                    Ok(label) => label,
                    Err(err) => return Err(ErrorCode::SearchError(err.to_string())),
                };

                outer_map.insert(label.clone(), inner_map.clone());
            }
        }
    }

    Ok(outer_map)
}

//
// Secret Service utilities
//

/// Find the secret service collection whose label is the given name.
///
/// The name `default` is treated specially and is interpreted as naming
/// the default collection regardless of its label (which might be different).
pub fn get_collection<'a>(ss: &'a SecretService, name: &str) -> Result<Collection<'a>> {
    let collection = if name.eq("default") {
        ss.get_default_collection().map_err(decode_error)?
    } else {
        let all = ss.get_all_collections().map_err(decode_error)?;
        let found = all
            .into_iter()
            .find(|c| c.get_label().map(|l| l.eq(name)).unwrap_or(false));
        found.ok_or(ErrorCode::NoEntry)?
    };
    if collection.is_locked().map_err(decode_error)? {
        collection.unlock().map_err(decode_error)?;
    }
    Ok(collection)
}

/// Create a secret service collection labeled with the given name.
///
/// If a collection with that name already exists, it is returned.
///
/// The name `default` is specially interpreted to mean the default collection,
/// which always exists.
pub fn create_collection<'a>(ss: &'a SecretService<'a>, name: &str) -> Result<Collection<'a>> {
    let collection = if name.eq("default") {
        ss.get_default_collection().map_err(decode_error)?
    } else {
        ss.create_collection(name, "").map_err(decode_error)?
    };
    Ok(collection)
}

/// Given an existing item, set its password.
pub fn set_item_password(item: &Item, password: &str) -> Result<()> {
    item.set_secret(password.as_bytes(), "text/plain")
        .map_err(decode_error)
}

/// Given an existing item, retrieve and decode its password.
pub fn get_item_password(item: &Item) -> Result<String> {
    let bytes = item.get_secret().map_err(decode_error)?;
    decode_password(bytes)
}

/// Given an existing item, delete it.
pub fn delete_item(item: &Item) -> Result<()> {
    item.delete().map_err(decode_error)
}

/// Given a slice of items, filter out the ones that have an explicit target
/// attribute that doesn't match the given target.
///
/// References to the matching items are returned in a new vector.
pub fn matching_target_items<'a>(
    source: &'a [Item<'a>],
    target: &str,
) -> Result<Vec<&'a Item<'a>>> {
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

/// Map underlying secret-service errors to crate errors with
/// appropriate annotation.
pub fn decode_error(err: Error) -> ErrorCode {
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
    use crate::credential::CredentialPersistence;
    use crate::{tests::generate_random_string, Entry, Error, Limit, List, Search};

    use super::{default_credential_builder, SsCredential};

    use std::collections::HashSet;

    #[test]
    fn test_persistence() {
        assert!(matches!(
            default_credential_builder().persistence(),
            CredentialPersistence::UntilDelete
        ))
    }

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
        let actual = credential
            .new_from_matching_item()
            .expect("Can't read credential");
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

    fn probe_collection(name: &str) -> bool {
        use secret_service::blocking::SecretService;
        use secret_service::EncryptionType;

        let ss =
            SecretService::connect(EncryptionType::Dh).expect("Can't connect to secret service");
        let result = super::get_collection(&ss, name).is_ok();
        result
    }

    fn delete_collection(name: &str) {
        use secret_service::blocking::SecretService;
        pub use secret_service::EncryptionType;

        let ss =
            SecretService::connect(EncryptionType::Dh).expect("Can't connect to secret service");
        let collection = super::get_collection(&ss, name).expect("Can't find collection to delete");
        collection.delete().expect("Can't delete collection");
    }

    #[test]
    #[ignore = "can't be run headless, because it needs to prompt"]
    fn test_create_new_target_collection() {
        let name = generate_random_string();
        let credential = SsCredential::new_with_target(Some(&name), &name, &name)
            .expect("Can't create credential for new collection");
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
    #[ignore = "can't be run headless, because it needs to prompt"]
    fn test_separate_targets_dont_interfere() {
        let name1 = generate_random_string();
        let name2 = generate_random_string();
        let credential1 = SsCredential::new_with_target(Some(&name1), &name1, &name1)
            .expect("Can't create credential1 with new collection");
        let entry1 = Entry::new_with_credential(Box::new(credential1));
        let credential2 = SsCredential::new_with_target(Some(&name2), &name1, &name1)
            .expect("Can't create credential2 with new collection");
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

    #[test]
    fn test_existing_target_works_as_expected() {
        let name1 = "test_keyring1";
        let name2 = "test_keyring2";
        if !probe_collection(name1) || !probe_collection(name2) {
            println!("Skipping target test since needed collections don't exist or are locked");
            return;
        }
        let credential1 = SsCredential::new_with_target(Some(name1), name1, name1)
            .expect("Can't create credential1 with new collection");
        let entry1 = Entry::new_with_credential(Box::new(credential1));
        let credential2 = SsCredential::new_with_target(Some(name2), name1, name1)
            .expect("Can't create credential2 with new collection");
        let entry2 = Entry::new_with_credential(Box::new(credential2));
        let entry3 = Entry::new(name1, name1).expect("Can't create entry in default collection");
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
    }

    #[test]
    fn test_search() {
        let name = generate_random_string();
        let entry = entry_new(&name, &name);
        let password = "search test password";
        entry
            .set_password(password)
            .expect("Not a Secret Service credential");
        let result = Search::new()
            .expect("Failed to build search")
            .by("service", &name);
        let list = List::list_credentials(result, Limit::All)
            .expect("Failed to parse string from HashMap result");

        let actual: &SsCredential = entry
            .get_credential()
            .downcast_ref()
            .expect("Not a Secret Service credential");

        let mut expected = format!("{}\n", actual.label);
        let attributes = &actual.attributes;
        for (key, value) in attributes {
            let attribute = format!("\t{}:\t{}\n", key, value);
            expected.push_str(attribute.as_str());
        }
        let expected_set: HashSet<&str> = expected.lines().collect();
        let result_set: HashSet<&str> = list.lines().collect();
        assert_eq!(expected_set, result_set, "Search results do not match");
        entry
            .delete_password()
            .expect("Couldn't delete test-search");
    }
}
