use crate::error::{KeyringError, Result};
use secret_service::{EncryptionType, SecretService};

pub struct Keyring<'a> {
    service: &'a str,
    username: &'a str,
}

// Eventually try to get collection into the Keyring struct?
impl<'a> Keyring<'a> {
    pub const fn new(service: &'a str, username: &'a str) -> Keyring<'a> {
        Keyring { service, username }
    }

    pub fn set_password(&self, password: &str) -> Result<()> {
        let ss = SecretService::new(EncryptionType::Dh)?;
        let collection = ss.get_default_collection()?;
        if collection.is_locked()? {
            collection.unlock()?;
        }
        let mut attrs = self.default_attributes();
        attrs.push(("application", "rust-keyring"));
        let label = &format!("Password for {} on {}", self.username, self.service)[..];
        collection.create_item(
            label,
            attrs,
            password.as_bytes(),
            true, // replace
            "text/plain",
        )?;
        Ok(())
    }

    pub fn get_password(&self) -> Result<String> {
        let ss = SecretService::new(EncryptionType::Dh)?;
        let collection = ss.get_default_collection()?;
        if collection.is_locked()? {
            collection.unlock()?;
        }
        let search = collection.search_items(self.default_attributes())?;
        let item = search.get(0).ok_or(KeyringError::NoPasswordFound)?;
        let secret_bytes = item.get_secret()?;
        let secret = String::from_utf8(secret_bytes)?;
        Ok(secret)
    }

    pub fn delete_password(&self) -> Result<()> {
        let ss = SecretService::new(EncryptionType::Dh)?;
        let collection = ss.get_default_collection()?;
        if collection.is_locked()? {
            collection.unlock()?;
        }
        let search = collection.search_items(self.default_attributes())?;
        let item = search.get(0).ok_or(KeyringError::NoPasswordFound)?;
        Ok(item.delete()?)
    }

    fn default_attributes(&self) -> Vec<(&'a str, &'a str)> {
        vec![("service", self.service), ("username", self.username)]
    }
}
