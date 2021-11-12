use secret_service::{EncryptionType, SecretService};

use crate::{KeyringError, Platform, PlatformIdentity, Result};

pub fn platform() -> Platform {
    Platform::Linux
}

pub use secret_service::Error;

pub fn set_password(map: &PlatformIdentity, password: &str) -> Result<()> {
    if let PlatformIdentity::Linux(map) = map {
        let ss =
            SecretService::new(EncryptionType::Dh).map_err(KeyringError::SecretServiceError)?;
        let collection = ss
            .get_default_collection()
            .map_err(KeyringError::SecretServiceError)?;
        if collection
            .is_locked()
            .map_err(KeyringError::SecretServiceError)?
        {
            collection
                .unlock()
                .map_err(KeyringError::SecretServiceError)?;
        }
        collection.create_item(
            map.label(),
            map.attributes(),
            password.as_bytes(),
            true, // replace
            "text/plain",
        )?;
        Ok(())
    } else {
        Err(KeyringError::BadIdentityMapPlatform)
    }
}

pub fn get_password(map: &PlatformIdentity) -> Result<String> {
    if let PlatformIdentity::Linux(map) = map {
        let ss =
            SecretService::new(EncryptionType::Dh).map_err(KeyringError::SecretServiceError)?;
        let collection = ss
            .get_default_collection()
            .map_err(KeyringError::SecretServiceError)?;
        if collection
            .is_locked()
            .map_err(KeyringError::SecretServiceError)?
        {
            collection
                .unlock()
                .map_err(KeyringError::SecretServiceError)?;
        }
        let search = collection
            .search_items(map.attributes())
            .map_err(KeyringError::SecretServiceError)?;
        let item = search.get(0).ok_or(KeyringError::NoPasswordFound)?;
        let secret_bytes = item.get_secret()?;
        // Linux keyring allows non-UTF8 values, but this library only supports adding UTF8 items
        // to the keyring, so this should only fail if we are trying to retrieve a non-UTF8
        // password that was added to the keyring by another library
        let password = String::from_utf8(secret_bytes).map_err(KeyringError::Parse)?;
        Ok(password)
    } else {
        Err(KeyringError::BadIdentityMapPlatform)
    }
}

pub fn delete_password(map: &PlatformIdentity) -> Result<()> {
    if let PlatformIdentity::Linux(map) = map {
        let ss =
            SecretService::new(EncryptionType::Dh).map_err(KeyringError::SecretServiceError)?;
        let collection = ss
            .get_default_collection()
            .map_err(KeyringError::SecretServiceError)?;
        if collection
            .is_locked()
            .map_err(KeyringError::SecretServiceError)?
        {
            collection
                .unlock()
                .map_err(KeyringError::SecretServiceError)?;
        }
        let search = collection
            .search_items(map.attributes())
            .map_err(KeyringError::SecretServiceError)?;
        let item = search.get(0).ok_or(KeyringError::NoPasswordFound)?;
        item.delete().map_err(KeyringError::SecretServiceError)?;
        Ok(())
    } else {
        Err(KeyringError::BadIdentityMapPlatform)
    }
}
