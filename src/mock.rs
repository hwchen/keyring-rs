/*!

# Mock Credential Store

To facilitate testing of clients, this crate provides a Mock credential store
that is platform-independent, provides no persistence, and allows the client
to specify the return values (including errors) for each call.

To use this credential store instead of the default, make this call during
application startup _before_ creating any entries:
```rust
# use keyring::{set_default_credential_builder, mock};
set_default_credential_builder(mock::default_credential_builder());
```

You can then create entries as you usually do, and call their usual methods
to set, get, and delete passwords.  There is no peristence between
runs, so getting a credential before setting it will always result
in a [NotFound](Error::NoEntry) error.

If you want a method call on an entry to fail in a specific way, you can
downcast the entry to a [MockCredential] and then call [set_error](MockCredential::set_error)
with the appropriate error.  The next entry method called on the credential
will fail with the error you set.  The error will then be cleared, so the next
call on the mock will operate as usual.  Here's a complete example:
```rust
# use keyring::{Entry, Error, mock, mock::MockCredential};
# keyring::set_default_credential_builder(mock::default_credential_builder());
let entry = Entry::new("service", "user").unwrap();
let mock: &MockCredential = entry.get_credential().downcast_ref().unwrap();
mock.set_error(Error::Invalid("mock error".to_string(), "takes precedence".to_string()));
entry.set_password("test").expect_err("error will override");
entry.set_password("test").expect("error has been cleared");
```
 */
use std::cell::RefCell;
use std::sync::Mutex;

use super::credential::{Credential, CredentialApi, CredentialBuilder, CredentialBuilderApi};
use super::error::{Error, Result};

/// The concrete mock credential
///
/// Mocks use an internal mutability pattern since entries are read-only.
/// The mutex is used to make sure these are Sync.
#[derive(Debug)]
pub struct MockCredential {
    pub inner: Mutex<RefCell<MockData>>,
}

impl Default for MockCredential {
    fn default() -> Self {
        Self {
            inner: Mutex::new(RefCell::new(Default::default())),
        }
    }
}

/// The (in-memory) persisted data for a mock credential.
///
/// We keep a password, but unlike most keystores
/// we also keep an intended error to return on the next call.
///
/// (Everything about this structure is public for transparency.
/// Most keystore implementation hide their internals.)
#[derive(Debug, Default)]
pub struct MockData {
    pub password: Option<String>,
    pub error: Option<Error>,
}

impl CredentialApi for MockCredential {
    /// Set a password on a mock credential.
    ///
    /// If there is an error in the mock, it will be returned
    /// and the password will _not_ be set.  The error will
    /// be cleared, so calling again will set the password.
    fn set_password(&self, password: &str) -> Result<()> {
        let mut inner = self.inner.lock().expect("Can't access mock data for set");
        let mut data = inner.get_mut();
        let err = data.error.take();
        match err {
            None => {
                data.password = Some(password.to_string());
                Ok(())
            }
            Some(err) => Err(err),
        }
    }

    /// Get the password from a mock credential, if any.
    ///
    /// If there is an error set in the mock, it will
    /// be returned instead of a password.
    fn get_password(&self) -> Result<String> {
        let mut inner = self.inner.lock().expect("Can't access mock data for get");
        let data = inner.get_mut();
        let err = data.error.take();
        match err {
            None => match &data.password {
                None => Err(Error::NoEntry),
                Some(val) => Ok(val.clone()),
            },
            Some(err) => Err(err),
        }
    }

    /// Delete the password in a mock credential
    ///
    /// If there is an error, it will be returned and
    /// the deletion will not happen.
    ///
    /// If there is no password, a [NoEntry](Error::NoEntry) error
    /// will be returned.
    fn delete_password(&self) -> Result<()> {
        let mut inner = self
            .inner
            .lock()
            .expect("Can't access mock data for delete");
        let mut data = inner.get_mut();
        let err = data.error.take();
        match err {
            None => match data.password {
                Some(_) => {
                    data.password = None;
                    Ok(())
                }
                None => Err(Error::NoEntry),
            },
            Some(err) => Err(err),
        }
    }

    /// Return this mock credential concrete object
    /// wrapped in the [Any](std::any::Any) trait,
    /// so it can be downcast.
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl MockCredential {
    /// Make a new mock credential.
    ///
    /// Since mocks have no persistence between sessions,
    /// new mocks always have no password.
    fn new_with_target(_target: Option<&str>, _service: &str, _user: &str) -> Result<Self> {
        Ok(Default::default())
    }

    /// Set an error to be returned from this mock credential.
    ///
    /// Error returns always take precedence over the normal
    /// behavior of the mock.  But once an error has been
    /// returned it is removed, so the mock works thereafter.
    pub fn set_error(&self, err: Error) {
        let mut inner = self
            .inner
            .lock()
            .expect("Can't access mock data for set_error");
        let mut data = inner.get_mut();
        data.error = Some(err);
    }
}

/// The builder for mock credentials.
pub struct MockCredentialBuilder {}

impl CredentialBuilderApi for MockCredentialBuilder {
    /// Build a mock credential for the given target, service, and user.
    ///
    /// Since mocks don't persist between sessions,  all mocks
    /// start off without passwords.
    fn build(&self, target: Option<&str>, service: &str, user: &str) -> Result<Box<Credential>> {
        let credential = MockCredential::new_with_target(target, service, user).unwrap();
        Ok(Box::new(credential))
    }

    /// Get an [Any][std::any::Any] reference to the mock credential builder.
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Return a mock credential builder for use by clients.
pub fn default_credential_builder() -> Box<CredentialBuilder> {
    Box::new(MockCredentialBuilder {})
}

#[cfg(test)]
mod tests {
    use super::MockCredential;
    use crate::{tests::generate_random_string, Entry, Error};

    fn entry_new(service: &str, user: &str) -> Entry {
        let credential = MockCredential::new_with_target(None, service, user).unwrap();
        Entry::new_with_credential(Box::new(credential))
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
    fn test_set_error() {
        let name = generate_random_string();
        let entry = entry_new(&name, &name);
        let password = "test ascii password";
        let mock: &MockCredential = entry
            .inner
            .as_any()
            .downcast_ref()
            .expect("Downcast failed");
        mock.set_error(Error::Invalid(
            "mock error".to_string(),
            "is an error".to_string(),
        ));
        assert!(
            matches!(entry.set_password(password), Err(Error::Invalid(_, _))),
            "set: No error"
        );
        entry
            .set_password(password)
            .expect("set: Error not cleared");
        mock.set_error(Error::NoEntry);
        assert!(
            matches!(entry.get_password(), Err(Error::NoEntry)),
            "get: No error"
        );
        let stored_password = entry.get_password().expect("get: Error not cleared");
        assert_eq!(
            stored_password, password,
            "Retrieved and set ascii passwords don't match"
        );
        mock.set_error(Error::TooLong("mock".to_string(), 3));
        assert!(
            matches!(entry.delete_password(), Err(Error::TooLong(_, 3))),
            "delete: No error"
        );
        entry.delete_password().expect("delete: Error not cleared");
        assert!(
            matches!(entry.get_password(), Err(Error::NoEntry)),
            "Able to read a deleted ascii password"
        )
    }
}
