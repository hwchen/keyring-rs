use bytes::Bytes;
use secret_service::{Collection, EncryptionType, Item, SecretService};

use crate::{Error as KeyError, ErrorCode, Platform, PlatformCredential, Result};

pub fn platform() -> Platform {
    Platform::Linux
}

use crate::attrs::LinuxCredential;
pub use secret_service::Error;

fn get_collection<'a>(ss: &'a SecretService) -> Result<Collection<'a>> {
    let collection = ss.get_default_collection().map_err(decode_error)?;
    if collection.is_locked().map_err(decode_error)? {
        collection.unlock().map_err(decode_error)?;
    }
    Ok(collection)
}

pub fn set_password(map: &PlatformCredential, password: &str) -> Result<()> {
    if let PlatformCredential::Linux(map) = map {
        let ss = SecretService::new(EncryptionType::Dh)
            .map_err(|err| KeyError::new_from_platform(ErrorCode::PlatformFailure, err))?;
        let collection = get_collection(&ss)?;
        collection
            .create_item(
                map.label(),
                map.attributes(),
                password.as_bytes(),
                true, // replace
                "text/plain",
            )
            .map_err(|err| KeyError::new_from_platform(ErrorCode::PlatformFailure, err))?;
        Ok(())
    } else {
        Err(ErrorCode::BadCredentialMapPlatform.into())
    }
}

pub fn get_password(map: &mut PlatformCredential) -> Result<String> {
    if let PlatformCredential::Linux(map) = map {
        let ss = SecretService::new(EncryptionType::Dh).map_err(decode_error)?;
        let collection = get_collection(&ss)?;
        let search = collection
            .search_items(map.attributes())
            .map_err(decode_error)?;
        let item = search
            .get(0)
            .ok_or_else(|| KeyError::new(ErrorCode::NoEntry))?;
        let bytes = Bytes::from(item.get_secret().map_err(decode_error)?);
        // Linux keyring allows non-UTF8 values, but this library only supports adding UTF8 items
        // to the keyring, so this should only fail if we are trying to retrieve a non-UTF8
        // password that was added to the keyring by another library
        decode_attributes(map, item);
        let password = String::from_utf8(bytes.to_vec())
            .map_err(|_| KeyError::new(ErrorCode::BadEncoding("password".to_string(), bytes)))?;
        Ok(password)
    } else {
        Err(ErrorCode::BadCredentialMapPlatform.into())
    }
}

pub fn delete_password(map: &PlatformCredential) -> Result<()> {
    if let PlatformCredential::Linux(map) = map {
        let ss = SecretService::new(EncryptionType::Dh).map_err(decode_error)?;
        let collection = get_collection(&ss)?;
        let search = collection
            .search_items(map.attributes())
            .map_err(decode_error)?;
        let item = search
            .get(0)
            .ok_or_else(|| KeyError::new(ErrorCode::NoEntry))?;
        item.delete().map_err(decode_error)?;
        Ok(())
    } else {
        Err(ErrorCode::BadCredentialMapPlatform.into())
    }
}

fn decode_error(err: Error) -> KeyError {
    match err {
        Error::Crypto(_) => KeyError::new_from_platform(ErrorCode::PlatformFailure, err),
        Error::Zbus(_) => KeyError::new_from_platform(ErrorCode::PlatformFailure, err),
        Error::ZbusMsg(_) => KeyError::new_from_platform(ErrorCode::PlatformFailure, err),
        Error::ZbusFdo(_) => KeyError::new_from_platform(ErrorCode::PlatformFailure, err),
        Error::Zvariant(_) => KeyError::new_from_platform(ErrorCode::PlatformFailure, err),
        Error::Locked => KeyError::new_from_platform(ErrorCode::NoStorageAccess, err),
        Error::NoResult => KeyError::new_from_platform(ErrorCode::NoStorageAccess, err),
        Error::Parse => KeyError::new_from_platform(ErrorCode::PlatformFailure, err),
        Error::Prompt => KeyError::new_from_platform(ErrorCode::NoStorageAccess, err),
    }
}

fn decode_attributes(map: &mut LinuxCredential, item: &Item) {
    if let Ok(label) = item.get_label() {
        map.label = label
    }
}
