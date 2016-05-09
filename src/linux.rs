use secret_service::{EncryptionType, SecretService};

use ::KeyringError;

pub struct Keyring<'a> {
    attributes: Vec<(&'a str, &'a str)>,
    service: &'a str,
    username: &'a str,
}

// Eventually try to get collection into the Keyring struct?
impl<'a> Keyring<'a> {

    pub fn new(service: &'a str, username: &'a str) -> Keyring<'a> {
        let attributes = vec![
            ("application", "rust-keyring"),
            ("service", service),
            ("username", username),
        ];
        Keyring {
            attributes: attributes,
            service: service,
            username: username,
        }
    }

    pub fn set_password(&self, password: &str) -> ::Result<()> {
        let ss = try!(SecretService::new(EncryptionType::Dh));
        let collection = try!(ss.get_default_collection());
        if collection.is_locked().unwrap() {
            try!(collection.unlock());
        }
        let label = &format!("Password for {} on {}", self.username, self.service)[..];
        try!(collection.create_item(
            label,
            self.attributes.clone(),
            password.as_bytes(),
            true, // replace
            "text/plain",
        ));
        Ok(())
    }

    pub fn get_password(&self) -> ::Result<String> {
        let ss = try!(SecretService::new(EncryptionType::Dh));
        let collection = try!(ss.get_default_collection());
        if collection.is_locked().unwrap() {
            try!(collection.unlock());
        }
        let search = try!(collection.search_items(self.attributes.clone()));
        let item = try!(search.get(0).ok_or(KeyringError::NoPasswordFound));
        let secret_bytes = try!(item.get_secret());
        let secret = try!(String::from_utf8(secret_bytes));
        Ok(secret)
    }

    pub fn delete_password(&self) -> ::Result<()> {
        let ss = try!(SecretService::new(EncryptionType::Dh));
        let collection = try!(ss.get_default_collection());
        if collection.is_locked().unwrap() {
            try!(collection.unlock());
        }
        let search = try!(collection.search_items(self.attributes.clone()));
        let item = try!(search.get(0).ok_or(KeyringError::NoPasswordFound));
        Ok(try!(item.delete()))
    }
}

