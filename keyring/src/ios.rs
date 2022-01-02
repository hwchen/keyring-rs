use crate::error::decode_password;
use crate::{Error as ErrorCode, Platform, PlatformCredential, Result};
use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};

pub fn platform() -> Platform {
    Platform::Ios
}

pub use security_framework::base::Error;

pub fn set_password(map: &PlatformCredential, password: &str) -> Result<()> {
    if let PlatformCredential::Ios(map) = map {
        set_generic_password(&map.service, &map.account, password.as_bytes())
            .map_err(decode_error)?;
        Ok(())
    } else {
        Err(ErrorCode::WrongCredentialPlatform)
    }
}

pub fn get_password(map: &mut PlatformCredential) -> Result<String> {
    if let PlatformCredential::Ios(map) = map {
        let password_bytes =
            get_generic_password(&map.service, &map.account).map_err(decode_error)?;
        decode_password(password_bytes.to_vec())
    } else {
        Err(ErrorCode::WrongCredentialPlatform)
    }
}

pub fn delete_password(map: &PlatformCredential) -> Result<()> {
    if let PlatformCredential::Ios(map) = map {
        delete_generic_password(&map.service, &map.account).map_err(decode_error)?;
        Ok(())
    } else {
        Err(ErrorCode::WrongCredentialPlatform)
    }
}

/// The Ios error codes used here are from:
/// https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-78/lib/SecBase.h.auto.html
fn decode_error(err: Error) -> ErrorCode {
    match err.code() {
        -25291 => ErrorCode::NoStorageAccess(err), // errSecNotAvailable
        -25292 => ErrorCode::NoStorageAccess(err), // errSecReadOnly
        -25300 => ErrorCode::NoEntry,              // errSecItemNotFound
        _ => ErrorCode::PlatformFailure(err),
    }
}
