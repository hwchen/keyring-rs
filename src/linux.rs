use secret_service::{Collection, EncryptionType, Item, SecretService};

use crate::{Error as ErrorCode, Platform, PlatformCredential, Result};

pub fn platform() -> Platform {
    Platform::Linux
}

use crate::credential::LinuxCredential;
pub use secret_service::Error;

fn get_collection<'a>(map: &LinuxCredential, ss: &'a SecretService) -> Result<Collection<'a>> {
    let collection = ss
        .get_collection_by_alias(map.collection.as_str())
        .map_err(decode_error)?;
    if collection.is_locked().map_err(decode_error)? {
        collection.unlock().map_err(decode_error)?;
    }
    Ok(collection)
}

pub fn set_password(map: &PlatformCredential, password: &str) -> Result<()> {
    if let PlatformCredential::Linux(map) = map {
        let ss = SecretService::new(EncryptionType::Dh).map_err(ErrorCode::PlatformFailure)?;
        let collection = get_collection(map, &ss)?;
        collection
            .create_item(
                map.label.as_str(),
                map.attributes(),
                password.as_bytes(),
                true, // replace
                "text/plain",
            )
            .map_err(ErrorCode::PlatformFailure)?;
        Ok(())
    } else {
        Err(ErrorCode::WrongCredentialPlatform)
    }
}

pub fn get_password(map: &mut PlatformCredential) -> Result<String> {
    if let PlatformCredential::Linux(map) = map {
        let ss = SecretService::new(EncryptionType::Dh).map_err(decode_error)?;
        let collection = get_collection(map, &ss)?;
        let search = collection
            .search_items(map.attributes())
            .map_err(decode_error)?;
        let item = search.get(0).ok_or(ErrorCode::NoEntry)?;
        let bytes = item.get_secret().map_err(decode_error)?;
        // Linux keyring allows non-UTF8 values, but this library only supports adding UTF8 items
        // to the keyring, so this should only fail if we are trying to retrieve a non-UTF8
        // password that was added to the keyring by another library
        decode_attributes(map, item);
        decode_password(bytes)
    } else {
        Err(ErrorCode::WrongCredentialPlatform)
    }
}

pub fn delete_password(map: &PlatformCredential) -> Result<()> {
    if let PlatformCredential::Linux(map) = map {
        let ss = SecretService::new(EncryptionType::Dh).map_err(decode_error)?;
        let collection = get_collection(map, &ss)?;
        let search = collection
            .search_items(map.attributes())
            .map_err(decode_error)?;
        let item = search.get(0).ok_or(ErrorCode::NoEntry)?;
        item.delete().map_err(decode_error)?;
        Ok(())
    } else {
        Err(ErrorCode::WrongCredentialPlatform)
    }
}

fn decode_password(bytes: Vec<u8>) -> Result<String> {
    String::from_utf8(bytes.clone()).map_err(|_| ErrorCode::BadEncoding(bytes))
}

fn decode_error(err: Error) -> ErrorCode {
    match err {
        Error::Crypto(_) => ErrorCode::PlatformFailure(err),
        Error::Zbus(_) => ErrorCode::PlatformFailure(err),
        Error::ZbusMsg(_) => ErrorCode::PlatformFailure(err),
        Error::ZbusFdo(_) => ErrorCode::PlatformFailure(err),
        Error::Zvariant(_) => ErrorCode::PlatformFailure(err),
        Error::Locked => ErrorCode::NoStorageAccess(err),
        Error::NoResult => ErrorCode::NoStorageAccess(err),
        Error::Parse => ErrorCode::PlatformFailure(err),
        Error::Prompt => ErrorCode::NoStorageAccess(err),
    }
}

fn decode_attributes(map: &mut LinuxCredential, item: &Item) {
    if let Ok(label) = item.get_label() {
        map.label = label
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bad_password() {
        // malformed sequences here taken from:
        // https://www.cl.cam.ac.uk/~mgk25/ucs/examples/UTF-8-test.txt
        for bytes in [b"\x80".to_vec(), b"\xbf".to_vec(), b"\xed\xa0\xa0".to_vec()] {
            match decode_password(bytes.clone()) {
                Err(ErrorCode::BadEncoding(str)) => assert_eq!(str, bytes),
                Err(other) => panic!(
                    "Bad password ({:?}) decode gave wrong error: {}",
                    bytes, other
                ),
                Ok(s) => panic!("Bad password ({:?}) decode gave results: {:?}", bytes, &s),
            }
        }
    }
}
