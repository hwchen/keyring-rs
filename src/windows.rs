use std::{convert::TryInto, str};

use bindings::windows::security::credentials::{PasswordCredential, PasswordVault};

use crate::{
    error::{ParseError, Result},
    KeyringError,
};

// Windows won't accept empty passwords
const EMPTY_PASSWORD: &str = "_keyring-windows-empty-password";
const ERROR_NOT_FOUND: u32 = 0x80070490;

pub(crate) mod bindings {
    ::windows::include_bindings!();
}

pub struct Keyring<'a> {
    service: &'a str,
    username: &'a str,
}

impl<'a> Keyring<'a> {
    pub fn new(service: &'a str, username: &'a str) -> Keyring<'a> {
        Keyring { service, username }
    }

    fn get_vault(&self) -> Result<PasswordVault> {
        Ok(PasswordVault::new()?)
    }

    fn get_password_credential(&self) -> Result<PasswordCredential> {
        let credential = PasswordCredential::new()?;
        credential.set_resource(self.service)?;

        Ok(credential)
    }

    pub fn set_password(&self, password: &str) -> Result<()> {
        let vault = self.get_vault()?;
        let credential = self.get_password_credential()?;
        let password = if password.is_empty() {
            // Windows does not support empty passwords
            EMPTY_PASSWORD.to_string()
        } else {
            password.to_string()
        };

        credential.set_user_name(self.username)?;
        credential
            .set_password(password)
            .map_err(windows_to_key_ring)?;

        vault.add(credential)?;
        Ok(())
    }

    pub fn get_password(&self) -> Result<String> {
        let vault = self.get_vault()?;
        let credential = vault
            .retrieve(self.service, self.username)
            .map_err(windows_to_key_ring)?;

        let password = credential
            .password()?
            .try_into()
            .map_err(|e| ParseError::Utf16(e))?;

        let password = if password == EMPTY_PASSWORD {
            "".to_string()
        } else {
            password
        };

        Ok(password)
    }

    pub fn delete_password(&self) -> Result<()> {
        let vault = self.get_vault()?;
        let credential = vault
            .retrieve(self.service, self.username)
            .map_err(windows_to_key_ring)?;
        vault.remove(credential)?;
        Ok(())
    }
}

fn windows_to_key_ring(error: windows::Error) -> KeyringError {
    match error.code().0 {
        ERROR_NOT_FOUND => KeyringError::NoPasswordFound,
        _ => KeyringError::OsError(error),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::error::KeyringError;

    #[test]
    fn test_basic() {
        let password_1 = "大根";
        let password_2 = "0xE5A4A7E6A0B9"; // Above in hex string

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

    #[test]
    fn test_no_password() {
        let keyring = Keyring::new("testservice", "test-no-password");
        let result = keyring.get_password();
        match result {
            Ok(_) => panic!("expected KeyringError::NoPassword, got Ok"),
            Err(KeyringError::NoPasswordFound) => (),
            Err(e) => panic!("expected KeyringError::NoPassword, got {:}", e),
        }

        let result = keyring.delete_password();
        match result {
            Ok(_) => panic!("expected Err(KeyringError::NoPassword), got Ok()"),
            Err(KeyringError::NoPasswordFound) => (),
            Err(e) => panic!("expected KeyringError::NoPassword, got {:}", e),
        }
    }
}
