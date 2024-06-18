/*!

# Keyring

This is a cross-platform library that does storage and retrieval of passwords
(or other secrets) in an underlying platform-specific secure store.
A top-level introduction to the library's usage, as well as a small code sample,
may be found in [the library's entry on crates.io](https://crates.io/crates/keyring).
Currently supported platforms are
Linux,
FreeBSD,
OpenBSD,
Windows,
macOS, and iOS.

## Design

This crate implements a very simple, platform-independent concrete object called an _entry_.
Each entry is identified by a <_service name_, _user name_> pair of UTF-8 strings,
optionally augmented by a _target_ string (which can be used to distinguish two entries
that have the same _service name_ and _user name_).
Entries support setting, getting, and forgetting (aka deleting) passwords (UTF-8 strings).

Entries provide persistence for their passwords by wrapping credentials held in platform-specific
credential stores.  The implementations of these platform-specific stores are captured
in two types (with associated traits):

- a _credential builder_, represented by the [CredentialBuilder] type
(and [CredentialBuilderApi](credential::CredentialBuilderApi) trait).  Credential
builders are given the identifying information provided for an entry and maps
it to the identifying information for a matching platform-specific credential.
- a _credential_, represented by the [Credential] type
(and [CredentialApi](credential::CredentialApi) trait).  The platform-specific credential
identified by a builder for an entry is what provides the secure storage for that entry's password.

## Crate-provided Credential Stores

This crate runs on several different platforms, and it provides one
or more implementations of credential stores on each platform.
These implementations work by mapping the data used to identify an entry
to data used to identify platform-specific storage objects.
For example, on macOS, the service and user names provided for an entry
are mapped to the service and user attributes that identify an element
in the macOS keychain.

Typically, platform-specific stores have a richer model of an entry than
the one used by this crate.  They expose their specific model in the
concrete credential objects they use to implement the Credential trait.
In order to allow clients to access this richer model, the Credential trait
has an [as_any](credential::CredentialApi::as_any) method that returns a
reference to the underlying
concrete object typed as [Any](std::any::Any), so that it can be downgraded to
its concrete type.

## Client-provided Credential Stores

In addition to the platform stores implemented by this crate, clients
are free to provide their own secure stores and use those.  There are
two mechanisms provided for this:

- Clients can give their desired credential builder to the crate
for use by the [Entry::new] and [Entry::new_with_target] calls.
This is done by making a call to [set_default_credential_builder].
The major advantage of this approach is that client code remains
independent of the credential builder being used.
- Clients can construct their concrete credentials directly and
then turn them into entries by using the [Entry::new_with_credential]
call. The major advantage of this approach is that credentials
can be identified however clients want, rather than being restricted
to the simple model used by this crate.

## Mock Credential Store

In addition to the platform-specific credential stores, this crate
also provides a mock credential store that clients can use to
test their code in a platform independent way.  The mock credential
store allows for pre-setting errors as well as password values to
be returned from [Entry] method calls.

## Interoperability with Third Parties

Each of the credential stores provided by this crate uses an underlying
platform-specific store that may also be used by modules written
in other languages.  If you want to interoperate with these third party
credential writers, then you will need to understand the details of how the
target, service name, and user name of this crate's generic model
are used to identify credentials in the platform-specific store.
These details are in the implementation of this crate's secure-storage
modules, and are documented in the headers of those modules.

(_N.B._ Since the included credential store implementations are platform-specific,
you may need to use the Platform drop-down on [docs.rs](https://docs.rs/keyring) to
view the storage module documentation for your desired platform.)

## Caveats

This module manipulates passwords as UTF-8 encoded strings,
so if a third party has stored an arbitrary byte string
then retrieving that password will return a [BadEncoding](Error::BadEncoding) error.
The returned error will have the raw bytes attached,
so you can access them.

While this crate's code is thread-safe,
accessing the _same_ entry from multiple threads
in close proximity may be unreliable (especially on Windows),
in that the underlying platform
store may actually execute those calls in a different
order than they are made. As long as you access a single entry from
only one thread at a time, multi-threading should be fine.

(N.B. Creating an entry is not the same as accessing it, because
entry creation doesn't go through the platform credential manager.
It's fine to create an entry on one thread and then immediately use
it on a different thread.  This is thoroughly tested on all platforms.)
 */
use std::collections::HashMap;

pub use credential::{Credential, CredentialBuilder};
pub use error::{Error, Result};
use keyring_search::{CredentialSearchResult, Error as SearchError, Limit, List, Search};

// Included keystore implementations and default choice thereof.

pub mod mock;

#[cfg(all(target_os = "linux", feature = "linux-keyutils"))]
pub mod keyutils;
#[cfg(all(
    target_os = "linux",
    feature = "secret-service",
    not(feature = "linux-no-secret-service")
))]
pub mod secret_service;
#[cfg(all(
    target_os = "linux",
    feature = "secret-service",
    not(feature = "linux-default-keyutils")
))]
use crate::secret_service as default;
#[cfg(all(
    target_os = "linux",
    feature = "linux-keyutils",
    any(feature = "linux-default-keyutils", not(feature = "secret-service"))
))]
use keyutils as default;
#[cfg(all(
    target_os = "linux",
    not(feature = "secret-service"),
    not(feature = "linux-keyutils")
))]
use mock as default;

#[cfg(all(target_os = "freebsd", feature = "secret-service"))]
pub mod secret_service;
#[cfg(all(target_os = "freebsd", feature = "secret-service"))]
use crate::secret_service as default;
#[cfg(all(target_os = "freebsd", not(feature = "secret-service")))]
use mock as default;

#[cfg(all(target_os = "openbsd", feature = "secret-service"))]
pub mod secret_service;
#[cfg(all(target_os = "openbsd", feature = "secret-service"))]
use crate::secret_service as default;
#[cfg(all(target_os = "openbsd", not(feature = "secret-service")))]
use mock as default;

#[cfg(all(target_os = "macos", feature = "platform-macos"))]
pub mod macos;
#[cfg(all(target_os = "macos", feature = "platform-macos"))]
use macos as default;
#[cfg(all(target_os = "macos", not(feature = "platform-macos")))]
use mock as default;

#[cfg(all(target_os = "windows", feature = "platform-windows"))]
pub mod windows;
#[cfg(all(target_os = "windows", not(feature = "platform-windows")))]
use mock as default;
#[cfg(all(target_os = "windows", feature = "platform-windows"))]
use windows as default;

#[cfg(all(target_os = "ios", feature = "platform-ios"))]
pub mod ios;
#[cfg(all(target_os = "ios", feature = "platform-ios"))]
use ios as default;
#[cfg(all(target_os = "ios", not(feature = "platform-ios")))]
use mock as default;

#[cfg(not(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "macos",
    target_os = "ios",
    target_os = "windows",
)))]
use mock as default;

pub mod credential;
pub mod error;

#[derive(Default, Debug)]
struct EntryBuilder {
    inner: Option<Box<CredentialBuilder>>,
}

static DEFAULT_BUILDER: std::sync::RwLock<EntryBuilder> =
    std::sync::RwLock::new(EntryBuilder { inner: None });

/// Set the credential builder used by default to create entries.
///
/// This is really meant for use by clients who bring their own credential
/// store and want to use it everywhere.  If you are using multiple credential
/// stores and want precise control over which credential is in which store,
/// then use [new_with_credential](Entry::new_with_credential).
///
/// This will block waiting for all other threads currently creating entries
/// to complete what they are doing. It's really meant to be called
/// at app startup before you start creating entries.
pub fn set_default_credential_builder(new: Box<CredentialBuilder>) {
    let mut guard = DEFAULT_BUILDER
        .write()
        .expect("Poisoned RwLock in keyring-rs: please report a bug!");
    guard.inner = Some(new);
}

fn build_default_credential(target: Option<&str>, service: &str, user: &str) -> Result<Entry> {
    lazy_static::lazy_static! {
        static ref DEFAULT: Box<CredentialBuilder> = default::default_credential_builder();
    }
    let guard = DEFAULT_BUILDER
        .read()
        .expect("Poisoned RwLock in keyring-rs: please report a bug!");
    let builder = match guard.inner.as_ref() {
        Some(builder) => builder,
        None => &DEFAULT,
    };
    let credential = builder.build(target, service, user)?;
    Ok(Entry { inner: credential })
}

#[derive(Debug)]
pub struct Entry {
    inner: Box<Credential>,
}

impl Entry {
    /// Create an entry for the given service and user.
    ///
    /// The default credential builder is used.
    pub fn new(service: &str, user: &str) -> Result<Entry> {
        build_default_credential(None, service, user)
    }

    /// Create an entry for the given target, service, and user.
    ///
    /// The default credential builder is used.
    pub fn new_with_target(target: &str, service: &str, user: &str) -> Result<Entry> {
        build_default_credential(Some(target), service, user)
    }

    /// Create an entry that uses the given platform credential for storage.
    pub fn new_with_credential(credential: Box<Credential>) -> Entry {
        Entry { inner: credential }
    }

    /// Set the password for this entry.
    ///
    /// Can return an [Ambiguous](Error::Ambiguous) error
    /// if there is more than one platform credential
    /// that matches this entry.  This can only happen
    /// on some platforms, and then only if a third-party
    /// application wrote the ambiguous credential.
    pub fn set_password(&self, password: &str) -> Result<()> {
        self.inner.set_password(password)
    }

    /// Retrieve the password saved for this entry.
    ///
    /// Returns a [NoEntry](Error::NoEntry) error if there isn't one.
    ///
    /// Can return an [Ambiguous](Error::Ambiguous) error
    /// if there is more than one platform credential
    /// that matches this entry.  This can only happen
    /// on some platforms, and then only if a third-party
    /// application wrote the ambiguous credential.
    pub fn get_password(&self) -> Result<String> {
        self.inner.get_password()
    }

    /// Delete the password for this entry.
    ///
    /// Returns a [NoEntry](Error::NoEntry) error if there isn't one.
    ///
    /// Can return an [Ambiguous](Error::Ambiguous) error
    /// if there is more than one platform credential
    /// that matches this entry.  This can only happen
    /// on some platforms, and then only if a third-party
    /// application wrote the ambiguous credential.
    pub fn delete_password(&self) -> Result<()> {
        self.inner.delete_password()
    }

    /// Return a reference to this entry's wrapped credential.
    ///
    /// The reference is of the [Any](std::any::Any) type so it can be
    /// downgraded to a concrete credential object.  The client must know
    /// what type of concrete object to cast to.
    pub fn get_credential(&self) -> &dyn std::any::Any {
        self.inner.as_any()
    }

    /// Default search method.
    ///
    /// Takes in a query and searches all possible options,
    /// filtering out duplicate results.
    pub fn search(query: &str) -> CredentialSearchResult {
        let mut results = vec![];
        let mut final_result = HashMap::new();
        let search = match Search::new() {
            Ok(search) => search,
            Err(err) => return Err(SearchError::SearchError(err.to_string())),
        };

        if let Ok(service_result) = search.by_service(query) {
            results.push(service_result)
        }

        if let Ok(target_result) = search.by_target(query) {
            results.push(target_result)
        }

        if let Ok(user_result) = search.by_user(query) {
            results.push(user_result)
        }

        if results.len() <= 1 {
            let result = results[0].clone();
            return Ok(result);
        }

        for index in 0..results.len() - 1 {
            if results[0] == results[index] {
                results.remove(index);
            }
        }

        for result in results {
            final_result.extend(result);
        }

        Ok(final_result)
    }
    /// Create entry from search results.
    ///
    /// Pass a `&CredentialSearchResult` and the ID to the credential.
    /// `CredentialSearchResult` is a bilevel hashmap: `HashMap<String, HashMap<String, String>>`,
    /// The outer map's key corresponds to the ID of the result from 1 to the length of the map.
    /// The inner map contains the keys and values of the metadata of the result, i.e.
    /// target, service, user, last modified/date written, etc. In the case of keyutils, the Linux
    /// Kernel keystore provides IDs for all credentials, the user must know the ID of the credential
    /// to manipulate and pass this value to `from_search_results`. Since keyutils only returns one
    /// result, this is the only valid parameter.
    /// # Example
    /// First result:
    /// ```rust no_run
    /// use keyring::Entry;
    ///
    /// let result = Entry::search("Foo");
    /// let entry = Entry::from_search_results(&result, 1);
    /// ```
    /// All results:
    /// ```rust no_run
    /// use keyring::Entry;
    ///
    /// let result = Entry::search("Foo");
    /// let size = result.as_ref().expect("No results").keys().len();
    /// let entries: Vec<Entry> = vec![];
    /// for index in 0..=size {
    ///     let entry = Entry::from_search_results(&result, index);
    /// }
    /// ```
    pub fn from_search_results(result: &CredentialSearchResult, id: usize) -> Result<Entry> {
        let result = match result {
            Ok(result) => result,
            Err(err) => {
                return Err(Error::Invalid(
                    "from search results".to_string(),
                    err.to_string(),
                ))
            }
        };

        let credential = match result.get_key_value(&id.to_string()) {
            Some(credential) => credential.1,
            None => return Err(Error::NoEntry),
        };

        default::entry_from_search(credential)
    }

    pub fn list_results(result: &CredentialSearchResult) -> String {
        list(result, None)
    }

    pub fn list_max(result: &CredentialSearchResult, limit: i64) -> String {
        list(result, Some(limit))
    }
}

fn list(result: &CredentialSearchResult, limit: Option<i64>) -> String {
    match limit {
        Some(limit) => List::list_credentials(result, Limit::Max(limit)),
        None => List::list_credentials(result, Limit::All),
    }
}

#[cfg(doctest)]
doc_comment::doctest!("../README.md", readme);

#[cfg(test)]
/// There are no actual tests in this module.
/// Instead, it contains generics that each keystore invokes in their tests,
/// passing their store-specific parameters for the generic ones.
//
// Since iOS doesn't use any of these generics, we allow dead code.
#[allow(dead_code)]
mod tests {
    use super::{credential::CredentialApi, Entry, Error, Result};

    /// Create a platform-specific credential given the constructor, service, and user
    pub fn entry_from_constructor<F, T>(f: F, service: &str, user: &str) -> Entry
    where
        F: FnOnce(Option<&str>, &str, &str) -> Result<T>,
        T: 'static + CredentialApi + Send + Sync,
    {
        match f(None, service, user) {
            Ok(credential) => Entry::new_with_credential(Box::new(credential)),
            Err(err) => {
                panic!("Couldn't create entry (service: {service}, user: {user}): {err:?}")
            }
        }
    }

    /// A basic round-trip unit test given an entry and a password.
    pub fn test_round_trip(case: &str, entry: &Entry, in_pass: &str) {
        entry
            .set_password(in_pass)
            .unwrap_or_else(|err| panic!("Can't set password for {case}: {err:?}"));
        let out_pass = entry
            .get_password()
            .unwrap_or_else(|err| panic!("Can't get password for {case}: {err:?}"));
        assert_eq!(
            in_pass, out_pass,
            "Passwords don't match for {case}: set='{in_pass}', get='{out_pass}'",
        );
        entry
            .delete_password()
            .unwrap_or_else(|err| panic!("Can't delete password for {case}: {err:?}"));
        let password = entry.get_password();
        assert!(
            matches!(password, Err(Error::NoEntry)),
            "Read deleted password for {case}",
        );
    }

    /// When tests fail, they leave keys behind, and those keys
    /// have to be cleaned up before the tests can be run again
    /// in order to avoid bad results.  So it's a lot easier just
    /// to have tests use a random string for key names to avoid
    /// the conflicts, and then do any needed cleanup once everything
    /// is working correctly.  So we export this function for tests to use.
    pub fn generate_random_string_of_len(len: usize) -> String {
        // from the Rust Cookbook:
        // https://rust-lang-nursery.github.io/rust-cookbook/algorithms/randomness.html
        use rand::{distributions::Alphanumeric, thread_rng, Rng};
        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(len)
            .map(char::from)
            .collect()
    }

    pub fn generate_random_string() -> String {
        generate_random_string_of_len(30)
    }

    pub fn test_empty_service_and_user<F>(f: F)
    where
        F: Fn(&str, &str) -> Entry,
    {
        let name = generate_random_string();
        let in_pass = "doesn't matter";
        test_round_trip("empty user", &f(&name, ""), in_pass);
        test_round_trip("empty service", &f("", &name), in_pass);
        test_round_trip("empty service & user", &f("", ""), in_pass);
    }

    pub fn test_missing_entry<F>(f: F)
    where
        F: FnOnce(&str, &str) -> Entry,
    {
        let name = generate_random_string();
        let entry = f(&name, &name);
        assert!(
            matches!(entry.get_password(), Err(Error::NoEntry)),
            "Missing entry has password"
        )
    }

    pub fn test_empty_password<F>(f: F)
    where
        F: FnOnce(&str, &str) -> Entry,
    {
        let name = generate_random_string();
        let entry = f(&name, &name);
        test_round_trip("empty password", &entry, "");
    }

    pub fn test_round_trip_ascii_password<F>(f: F)
    where
        F: FnOnce(&str, &str) -> Entry,
    {
        let name = generate_random_string();
        let entry = f(&name, &name);
        test_round_trip("ascii password", &entry, "test ascii password");
    }

    pub fn test_round_trip_non_ascii_password<F>(f: F)
    where
        F: FnOnce(&str, &str) -> Entry,
    {
        let name = generate_random_string();
        let entry = f(&name, &name);
        test_round_trip("non-ascii password", &entry, "このきれいな花は桜です");
    }

    pub fn test_update<F>(f: F)
    where
        F: FnOnce(&str, &str) -> Entry,
    {
        let name = generate_random_string();
        let entry = f(&name, &name);
        test_round_trip("initial ascii password", &entry, "test ascii password");
        test_round_trip(
            "updated non-ascii password",
            &entry,
            "このきれいな花は桜です",
        );
    }
}
