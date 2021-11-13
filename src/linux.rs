use secret_service::{Collection, EncryptionType, SecretService};

use crate::{Error as KeyError, KeyringError, Platform, PlatformIdentity, Result};

pub fn platform() -> Platform {
    Platform::Linux
}

pub use secret_service::Error;

fn get_collection<'a>(ss: &'a SecretService) -> Result<Collection<'a>> {
    let collection = ss
        .get_default_collection()
        .map_err(|err| KeyError::new_from_platform(KeyringError::NoStorage, err))?;
    if collection
        .is_locked()
        .map_err(|err| KeyError::new_from_platform(KeyringError::PlatformFailure, err))?
    {
        collection
            .unlock()
            .map_err(|err| KeyError::new_from_platform(KeyringError::NoStorage, err))?;
    }
    Ok(collection)
}

pub fn set_password(map: &PlatformIdentity, password: &str) -> Result<()> {
    if let PlatformIdentity::Linux(map) = map {
        let ss = SecretService::new(EncryptionType::Dh)
            .map_err(|err| KeyError::new_from_platform(KeyringError::PlatformFailure, err))?;
        let collection = get_collection(&ss)?;
        collection
            .create_item(
                map.label(),
                map.attributes(),
                password.as_bytes(),
                true, // replace
                "text/plain",
            )
            .map_err(|err| KeyError::new_from_platform(KeyringError::PlatformFailure, err))?;
        Ok(())
    } else {
        Err(KeyringError::BadIdentityMapPlatform.into())
    }
}

pub fn get_password(map: &PlatformIdentity) -> Result<String> {
    if let PlatformIdentity::Linux(map) = map {
        let ss = SecretService::new(EncryptionType::Dh)
            .map_err(|err| KeyError::new_from_platform(KeyringError::PlatformFailure, err))?;
        let collection = get_collection(&ss)?;
        let search = collection
            .search_items(map.attributes())
            .map_err(|err| KeyError::new_from_platform(KeyringError::PlatformFailure, err))?;
        let item = search
            .get(0)
            .ok_or_else(|| KeyError::new(KeyringError::NoEntry))?;
        let secret_bytes = item
            .get_secret()
            .map_err(|err| KeyError::new_from_platform(KeyringError::PlatformFailure, err))?;
        // Linux keyring allows non-UTF8 values, but this library only supports adding UTF8 items
        // to the keyring, so this should only fail if we are trying to retrieve a non-UTF8
        // password that was added to the keyring by another library
        let password = String::from_utf8(secret_bytes)
            .map_err(|_| KeyError::new(KeyringError::BadEncoding))?;
        Ok(password)
    } else {
        Err(KeyringError::BadIdentityMapPlatform.into())
    }
}

pub fn delete_password(map: &PlatformIdentity) -> Result<()> {
    if let PlatformIdentity::Linux(map) = map {
        let ss = SecretService::new(EncryptionType::Dh)
            .map_err(|err| KeyError::new_from_platform(KeyringError::PlatformFailure, err))?;
        let collection = get_collection(&ss)?;
        let search = collection
            .search_items(map.attributes())
            .map_err(|err| KeyError::new_from_platform(KeyringError::PlatformFailure, err))?;
        let item = search
            .get(0)
            .ok_or_else(|| KeyError::new(KeyringError::NoEntry))?;
        item.delete()
            .map_err(|err| KeyError::new_from_platform(KeyringError::PlatformFailure, err))?;
        Ok(())
    } else {
        Err(KeyringError::BadIdentityMapPlatform.into())
    }
}
