use std::cell::RefCell;
use std::sync::Mutex;

use super::credential::{Credential, CredentialApi, CredentialBuilder, CredentialBuilderApi};
use super::error::{Error, Result};

#[derive(Debug)]
pub struct MockCredential {
    inner: Mutex<RefCell<MockData>>,
}

impl Default for MockCredential {
    fn default() -> Self {
        Self {
            inner: Mutex::new(RefCell::new(Default::default())),
        }
    }
}

#[derive(Debug, Default)]
struct MockData {
    password: Option<String>,
    error: Option<Error>,
}

impl CredentialApi for MockCredential {
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

    fn delete_password(&self) -> Result<()> {
        let mut inner = self
            .inner
            .lock()
            .expect("Can't access mock data for delete");
        let mut data = inner.get_mut();
        let err = data.error.take();
        match err {
            None => {
                data.password = None;
                Ok(())
            }
            Some(err) => Err(err),
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl MockCredential {
    fn new_with_target(_target: Option<&str>, _service: &str, _user: &str) -> Result<Self> {
        Ok(Default::default())
    }

    pub fn set_error(&self, err: Error) {
        let mut inner = self
            .inner
            .lock()
            .expect("Can't access mock data for set_error");
        let mut data = inner.get_mut();
        data.error = Some(err);
    }
}

pub struct MockCredentialBuilder {}

impl CredentialBuilderApi for MockCredentialBuilder {
    fn build(&self, target: Option<&str>, service: &str, user: &str) -> Result<Box<Credential>> {
        let credential = MockCredential::new_with_target(target, service, user).unwrap();
        Ok(Box::new(credential))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

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
        mock.set_error(Error::InvalidArgument("mock error".to_string()));
        assert!(
            matches!(entry.set_password(password), Err(Error::InvalidArgument(_))),
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
