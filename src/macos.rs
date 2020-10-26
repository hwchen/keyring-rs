use crate::error::Result;
use security_framework::os::macos::keychain::SecKeychain;
use security_framework::os::macos::passwords::find_generic_password;

use std::path::Path;
pub struct Keyring<'a> {
    service: &'a str,
    username: &'a str,
    path: Option<&'a Path>
}

// Eventually try to get collection into the Keyring struct?
impl<'a> Keyring<'a> {
    pub fn new(service: &'a str, username: &'a str) -> Keyring<'a> {
        Keyring { service, username, path: None }
    }

    #[cfg(feature = "macos-specify-keychain")]
    pub fn use_keychain(service: &'a str, username: &'a str, path: &'a Path) -> Keyring<'a> {
        Keyring { service, username, path: Some(path) }
    }

    fn get_keychain(&self) -> security_framework::base::Result<SecKeychain> {
        match self.path {
            Some(path) => SecKeychain::open(path),
            _ => SecKeychain::default()
        }
    }

    pub fn set_password(&self, password: &str) -> Result<()> {
        self.get_keychain()?.set_generic_password(
            self.service,
            self.username,
            password.as_bytes(),
        )?;

        Ok(())
    }

    pub fn get_password(&self) -> Result<String> {
        let (password_bytes, _) = find_generic_password(Some(&[self.get_keychain()?]), self.service, self.username)?;

        // Mac keychain allows non-UTF8 values, but this library only supports adding UTF8 items
        // to the keychain, so this should only fail if we are trying to retrieve a non-UTF8
        // password that was added to the keychain by another library

        let password = String::from_utf8(password_bytes.to_vec())?;

        Ok(password)
    }

    pub fn delete_password(&self) -> Result<()> {
        let (_, item) = find_generic_password(Some(&[self.get_keychain()?]), self.service, self.username)?;

        item.delete();

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_basic() {
        let password_1 = "大根";
        let password_2 = "0xE5A4A7E6A0B9"; // Above in hex string

        // run as root to access system keychain
        #[cfg(feature = "macos-specify-keychain")]
        let keyring = Keyring::use_keychain("testservice", "testuser", Path::new("/Library/Keychains/System.keychain"));
        #[cfg(not(feature = "macos-specify-keychain"))]
        let keyring = Keyring::new("testservice", "testuser");

        keyring.set_password(password_1).unwrap();
        let res_1 = keyring.get_password().unwrap();
        println!("{}:{}", res_1, password_1);
        assert_eq!(res_1, password_1);

        keyring.set_password(password_2).unwrap();
        let res_2 = keyring.get_password().unwrap();
        println!("{}:{}", res_2, password_2);
        assert_eq!(res_2, password_2);

        keyring.delete_password().unwrap();
    }
}
