use byteorder::{ByteOrder, LittleEndian};
use bytes::{Bytes, BytesMut};
use std::iter::once;
use std::mem::MaybeUninit;
use std::slice;
use std::str;
use winapi::shared::minwindef::FILETIME;
use winapi::shared::winerror::{
    ERROR_BAD_USERNAME, ERROR_INVALID_FLAGS, ERROR_INVALID_PARAMETER, ERROR_NOT_FOUND,
    ERROR_NO_SUCH_LOGON_SESSION,
};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::wincred::{
    CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_MAX_CREDENTIAL_BLOB_SIZE,
    CRED_MAX_GENERIC_TARGET_NAME_LENGTH, CRED_MAX_STRING_LENGTH, CRED_MAX_USERNAME_LENGTH,
    CRED_PERSIST_ENTERPRISE, CRED_TYPE_GENERIC, PCREDENTIALW, PCREDENTIAL_ATTRIBUTEW,
};

use crate::attrs::WinCredential;
use crate::{Error as KeyError, ErrorCode, Platform, PlatformCredential, Result};

pub fn platform() -> Platform {
    Platform::Windows
}

#[derive(Debug)]
pub struct Error(u32); // Windows error codes are long ints

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.0 {
            ERROR_NO_SUCH_LOGON_SESSION => write!(f, "Windows ERROR_NO_SUCH_LOGON_SESSION"),
            ERROR_NOT_FOUND => write!(f, "Windows ERROR_NOT_FOUND"),
            ERROR_BAD_USERNAME => write!(f, "Windows ERROR_BAD_USERNAME"),
            ERROR_INVALID_FLAGS => write!(f, "Windows ERROR_INVALID_FLAGS"),
            ERROR_INVALID_PARAMETER => write!(f, "Windows ERROR_INVALID_PARAMETER"),
            err => write!(f, "Windows error code {}", err),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

// DWORD is u32
// LPCWSTR is *const u16
// BOOL is i32 (false = 0, true = 1)
// PCREDENTIALW = *mut CREDENTIALW
pub fn set_password(map: &PlatformCredential, password: &str) -> Result<()> {
    if let PlatformCredential::Win(map) = map {
        validate_attributes(map, password)?;
        let mut username = to_wstr(&map.username);
        let mut target_name = to_wstr(&map.target_name);
        let mut target_alias = to_wstr(&map.target_alias);
        let mut comment = to_wstr(&map.comment);
        // Password strings are converted to UTF-16, because that's the native
        // charset for Windows strings.  This allows editing of the password in
        // the Windows native UI.  But the storage for the credential is actually
        // a little-endian blob, because passwords can contain anything.
        let blob_u16 = to_wstr_no_null(password);
        let mut password_blob = BytesMut::with_capacity(blob_u16.len() * 2);
        LittleEndian::write_u16_into(&blob_u16, &mut password_blob);
        let blob_len = password_blob.len() as u32;
        let flags = 0;
        let cred_type = CRED_TYPE_GENERIC;
        let persist = CRED_PERSIST_ENTERPRISE;
        // Ignored by CredWriteW
        let last_written = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        // TODO: Allow setting attributes on Windows credentials
        let attribute_count = 0;
        let attributes: PCREDENTIAL_ATTRIBUTEW = std::ptr::null_mut();
        let mut credential = CREDENTIALW {
            Flags: flags,
            Type: cred_type,
            TargetName: target_name.as_mut_ptr(),
            Comment: comment.as_mut_ptr(),
            LastWritten: last_written,
            CredentialBlobSize: blob_len,
            CredentialBlob: password_blob.as_mut_ptr(),
            Persist: persist,
            AttributeCount: attribute_count,
            Attributes: attributes,
            TargetAlias: target_alias.as_mut_ptr(),
            UserName: username.as_mut_ptr(),
        };
        // raw pointer to credential, is coerced from &mut
        let pcredential: PCREDENTIALW = &mut credential;
        // Call windows API
        match unsafe { CredWriteW(pcredential, 0) } {
            0 => Err(decode_error()),
            _ => Ok(()),
        }
    } else {
        Err(ErrorCode::BadCredentialMapPlatform.into())
    }
}

pub fn get_password(map: &mut PlatformCredential) -> Result<String> {
    if let PlatformCredential::Win(map) = map {
        validate_attributes(map, "")?;
        let target_name = to_wstr(&map.target_name);
        // passing uninitialized pcredential.
        // Should be ok; it's freed by a windows api call CredFree.
        let mut pcredential = MaybeUninit::uninit();
        let cred_type = CRED_TYPE_GENERIC;
        let result =
            unsafe { CredReadW(target_name.as_ptr(), cred_type, 0, pcredential.as_mut_ptr()) };
        match result {
            0 => Err(decode_error()),
            _ => {
                let pcredential = unsafe { pcredential.assume_init() };
                // Dereferencing pointer to credential
                let credential: CREDENTIALW = unsafe { *pcredential };
                decode_attributes(map, &credential);
                let password = decode_password(&credential);
                // Free the credential
                unsafe {
                    CredFree(pcredential as *mut _);
                }
                password
            }
        }
    } else {
        Err(ErrorCode::BadCredentialMapPlatform.into())
    }
}

pub fn delete_password(map: &PlatformCredential) -> Result<()> {
    if let PlatformCredential::Win(map) = map {
        validate_attributes(map, "")?;
        let target_name = to_wstr(&map.target_name);
        let cred_type = CRED_TYPE_GENERIC;
        match unsafe { CredDeleteW(target_name.as_ptr(), cred_type, 0) } {
            0 => Err(decode_error()),
            _ => Ok(()),
        }
    } else {
        Err(ErrorCode::BadCredentialMapPlatform.into())
    }
}

fn validate_attributes(map: &WinCredential, password: &str) -> Result<()> {
    if map.username.len() > CRED_MAX_USERNAME_LENGTH as usize {
        return Err(KeyError::new(ErrorCode::TooLong(
            String::from("username"),
            CRED_MAX_USERNAME_LENGTH,
        )));
    }
    if map.target_name.len() > CRED_MAX_GENERIC_TARGET_NAME_LENGTH as usize {
        return Err(KeyError::new(ErrorCode::TooLong(
            String::from("target name"),
            CRED_MAX_GENERIC_TARGET_NAME_LENGTH,
        )));
    }
    if map.target_alias.len() > CRED_MAX_STRING_LENGTH as usize {
        return Err(KeyError::new(ErrorCode::TooLong(
            String::from("target alias"),
            CRED_MAX_STRING_LENGTH,
        )));
    }
    if map.comment.len() > CRED_MAX_STRING_LENGTH as usize {
        return Err(KeyError::new(ErrorCode::TooLong(
            String::from("comment"),
            CRED_MAX_STRING_LENGTH,
        )));
    }
    if password.len() > CRED_MAX_CREDENTIAL_BLOB_SIZE as usize {
        return Err(KeyError::new(ErrorCode::TooLong(
            String::from("password"),
            CRED_MAX_CREDENTIAL_BLOB_SIZE,
        )));
    }
    Ok(())
}

fn decode_error() -> KeyError {
    match unsafe { GetLastError() } {
        ERROR_NOT_FOUND => KeyError::new_from_platform(ErrorCode::NoEntry, Error(ERROR_NOT_FOUND)),
        ERROR_NO_SUCH_LOGON_SESSION => KeyError::new_from_platform(
            ErrorCode::NoStorageAccess,
            Error(ERROR_NO_SUCH_LOGON_SESSION),
        ),
        err => KeyError::new_from_platform(ErrorCode::PlatformFailure, Error(err)),
    }
}

fn decode_attributes(map: &mut WinCredential, credential: &CREDENTIALW) {
    map.username = unsafe { from_wstr(credential.UserName) };
    map.comment = unsafe { from_wstr(credential.Comment) };
    map.target_alias = unsafe { from_wstr(credential.TargetAlias) };
}

fn decode_password(credential: &CREDENTIALW) -> Result<String> {
    // get password blob
    let blob_pointer: *const u8 = credential.CredentialBlob;
    let blob_len: usize = credential.CredentialBlobSize as usize;
    let blob = Bytes::from(unsafe { slice::from_raw_parts(blob_pointer, blob_len) });
    // 3rd parties may write credential data with an odd number of bytes,
    // so we make sure that we don't try to decode those as utf16
    if blob.len() % 2 != 0 {
        let err = KeyError::new(ErrorCode::BadEncoding(String::from("password"), blob));
        return Err(err);
    }
    // Now we know this _can_ be a UTF-16 string, so convert it to
    // as UTF-16 vector and then try to decode it.
    let mut blob_u16 = vec![0; blob.len() / 2];
    LittleEndian::read_u16_into(&blob.to_vec(), &mut blob_u16);
    String::from_utf16(&blob_u16)
        .map_err(|_| KeyError::new(ErrorCode::BadEncoding(String::from("password"), blob)))
}

fn to_wstr(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(once(0)).collect()
}

fn to_wstr_no_null(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

unsafe fn from_wstr(ws: *const u16) -> String {
    let len = (0..).take_while(|&i| *ws.offset(i) != 0).count();
    let slice = std::slice::from_raw_parts(ws, len);
    String::from_utf16_lossy(slice)
}
