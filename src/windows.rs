/*!

# Windows Credential Manager credential store

This module uses Windows Generic credentials to store entries.
These are identified by a single string (called their _target name_).
They also have a number of non-identifying but manipulable attributes:
a _username_, a _comment_, and a _target alias_.

For a given <_service_, _username_> pair,
this module uses the concatenated string `username.service`
as the mapped credential's _target name_, and
fills the _username_ and _comment_ fields with appropriate strings.
(This convention allows multiple users to store passwords for the same service.)

Because the Windows credential manager doesn't support multiple collections of credentials,
and because many Windows programs use _only_ the service name as the credential _target name_,
the `Entry::new_with_target` call uses the `target` parameter as the credential's _target name_
rather than concatenating the username and service.
So if you have a custom algorithm you want to use for computing the Windows target name,
you can specify the target name directly.  (You still need to provide a service and username,
because they are used in the credential's metadata.)

## Caveat

Reads and writes of the same entry from multiple threads in close proximity
are not guaranteed to be serialized by the Windows Credential Manager in
the order in which they were made.  There are tests of this behavior in the
test suite of this crate, and they have been observed to fail in both
Windows 10 and Windows 11.
*/
use byteorder::{ByteOrder, LittleEndian};
use std::iter::once;
use std::mem::MaybeUninit;
use std::str;
use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_BAD_USERNAME, ERROR_INVALID_FLAGS, ERROR_INVALID_PARAMETER,
    ERROR_NOT_FOUND, ERROR_NO_SUCH_LOGON_SESSION, FILETIME,
};
use windows_sys::Win32::Security::Credentials::{
    CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CREDENTIAL_ATTRIBUTEW, CRED_FLAGS,
    CRED_MAX_CREDENTIAL_BLOB_SIZE, CRED_MAX_GENERIC_TARGET_NAME_LENGTH, CRED_MAX_STRING_LENGTH,
    CRED_MAX_USERNAME_LENGTH, CRED_PERSIST_ENTERPRISE, CRED_TYPE_GENERIC,
};

use crate::Entry;

use super::credential::{Credential, CredentialApi, CredentialBuilder, CredentialBuilderApi};
use super::error::{Error as ErrorCode, Result};

/// The representation of a Windows Generic credential.
///
/// See the module header for the meanings of these fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinCredential {
    pub username: String,
    pub target_name: String,
    pub target_alias: String,
    pub comment: String,
}

// Windows API type mappings:
// DWORD is u32
// LPCWSTR is *const u16
// BOOL is i32 (false = 0, true = 1)
// PCREDENTIALW = *mut CREDENTIALW

impl CredentialApi for WinCredential {
    /// Create and write a credential with password for this entry.
    ///
    /// The new credential replaces any existing one in the store.
    /// Since there is only one credential with a given _target name_,
    /// there is no chance of ambiguity.
    fn set_password(&self, password: &str) -> Result<()> {
        self.validate_attributes(password)?;
        let mut username = to_wstr(&self.username);
        let mut target_name = to_wstr(&self.target_name);
        let mut target_alias = to_wstr(&self.target_alias);
        let mut comment = to_wstr(&self.comment);
        // Password strings are converted to UTF-16, because that's the native
        // charset for Windows strings.  This allows editing of the password in
        // the Windows native UI.  But the storage for the credential is actually
        // a little-endian blob, because passwords can contain anything.
        let blob_u16 = to_wstr_no_null(password);
        let mut blob = vec![0; blob_u16.len() * 2];
        LittleEndian::write_u16_into(&blob_u16, &mut blob);
        let blob_len = blob.len() as u32;
        let flags = CRED_FLAGS::default();
        let cred_type = CRED_TYPE_GENERIC;
        let persist = CRED_PERSIST_ENTERPRISE;
        // Ignored by CredWriteW
        let last_written = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let attribute_count = 0;
        let attributes: *mut CREDENTIAL_ATTRIBUTEW = std::ptr::null_mut();
        let mut credential = CREDENTIALW {
            Flags: flags,
            Type: cred_type,
            TargetName: target_name.as_mut_ptr(),
            Comment: comment.as_mut_ptr(),
            LastWritten: last_written,
            CredentialBlobSize: blob_len,
            CredentialBlob: blob.as_mut_ptr(),
            Persist: persist,
            AttributeCount: attribute_count,
            Attributes: attributes,
            TargetAlias: target_alias.as_mut_ptr(),
            UserName: username.as_mut_ptr(),
        };
        // raw pointer to credential, is coerced from &mut
        let p_credential: *const CREDENTIALW = &mut credential;
        // Call windows API
        match unsafe { CredWriteW(p_credential, 0) } {
            0 => Err(decode_error()),
            _ => Ok(()),
        }
    }

    /// Look up the password for this entry, if any.
    ///
    /// Returns a [NoEntry](ErrorCode::NoEntry) error if there is no
    /// credential in the store.
    fn get_password(&self) -> Result<String> {
        self.extract_from_platform(extract_password)
    }

    /// Delete the underlying generic credential for this entry, if any.
    ///
    /// Returns a [NoEntry](ErrorCode::NoEntry) error if there is no
    /// credential in the store.
    fn delete_password(&self) -> Result<()> {
        self.validate_attributes("")?;
        let target_name = to_wstr(&self.target_name);
        let cred_type = CRED_TYPE_GENERIC;
        match unsafe { CredDeleteW(target_name.as_ptr(), cred_type, 0) } {
            0 => Err(decode_error()),
            _ => Ok(()),
        }
    }

    /// Return the underlying concrete object with an `Any` type so that it can
    /// be downgraded to a [WinCredential] for platform-specific processing.
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl WinCredential {
    fn validate_attributes(&self, password: &str) -> Result<()> {
        if self.username.len() > CRED_MAX_USERNAME_LENGTH as usize {
            return Err(ErrorCode::TooLong(
                String::from("user"),
                CRED_MAX_USERNAME_LENGTH,
            ));
        }
        if self.target_name.is_empty() {
            return Err(ErrorCode::Invalid(
                "target".to_string(),
                "cannot be empty".to_string(),
            ));
        }
        if self.target_name.len() > CRED_MAX_GENERIC_TARGET_NAME_LENGTH as usize {
            return Err(ErrorCode::TooLong(
                String::from("target"),
                CRED_MAX_GENERIC_TARGET_NAME_LENGTH,
            ));
        }
        if self.target_alias.len() > CRED_MAX_STRING_LENGTH as usize {
            return Err(ErrorCode::TooLong(
                String::from("target alias"),
                CRED_MAX_STRING_LENGTH,
            ));
        }
        if self.comment.len() > CRED_MAX_STRING_LENGTH as usize {
            return Err(ErrorCode::TooLong(
                String::from("comment"),
                CRED_MAX_STRING_LENGTH,
            ));
        }
        // We're going to store the password as UTF-16, so make sure to consider its length as UTF-16.
        // `encode_utf16` gives us the count of `u16`s, so we multiply by 2 to get the number of bytes.
        if password.encode_utf16().count() * 2 > CRED_MAX_CREDENTIAL_BLOB_SIZE as usize {
            return Err(ErrorCode::TooLong(
                String::from("password"),
                CRED_MAX_CREDENTIAL_BLOB_SIZE,
            ));
        }
        Ok(())
    }

    /// Construct a credential from this credential's underlying Generic credential.
    ///
    /// This can be useful for seeing modifications made by a third party.
    pub fn get_credential(&self) -> Result<Self> {
        self.extract_from_platform(Self::extract_credential)
    }

    fn extract_from_platform<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&CREDENTIALW) -> Result<T>,
    {
        self.validate_attributes("")?;
        let mut p_credential = MaybeUninit::uninit();
        // at this point, p_credential is just a pointer to nowhere.
        // The allocation happens in the `CredReadW` call below.
        let result = {
            let cred_type = CRED_TYPE_GENERIC;
            let target_name = to_wstr(&self.target_name);
            unsafe {
                CredReadW(
                    target_name.as_ptr(),
                    cred_type,
                    0,
                    p_credential.as_mut_ptr(),
                )
            }
        };
        match result {
            0 => {
                // `CredReadW` failed, so no allocation has been done, so no free needs to be done
                Err(decode_error())
            }
            _ => {
                // `CredReadW` succeeded, so p_credential points at an allocated credential.
                // To do anything with it, we need to cast it to the right type.  That takes two steps:
                // first we remove the "uninitialized" guard from around it, then we reinterpret it as a
                // pointer to the right structure type.
                let p_credential = unsafe { p_credential.assume_init() };
                let w_credential: CREDENTIALW = unsafe { *p_credential };
                // Now we can apply the passed extractor function to the credential.
                let result = f(&w_credential);
                // Finally, we free the allocated credential.
                unsafe { CredFree(p_credential as *mut _) };
                result
            }
        }
    }

    fn extract_credential(w_credential: &CREDENTIALW) -> Result<Self> {
        Ok(Self {
            username: unsafe { from_wstr(w_credential.UserName) },
            target_name: unsafe { from_wstr(w_credential.TargetName) },
            target_alias: unsafe { from_wstr(w_credential.TargetAlias) },
            comment: unsafe { from_wstr(w_credential.Comment) },
        })
    }

    /// Create a credential for the given target, service, and user.
    ///
    /// Creating a credential does not create a matching Generic credential
    /// in the Windows Credential Manager.
    /// If there isn't already one there, it will be created only
    /// when [set_password](WinCredential::set_password) is
    /// called.
    pub fn new_with_target(
        target: Option<&str>,
        service: &str,
        user: &str,
    ) -> Result<WinCredential> {
        const VERSION: &str = env!("CARGO_PKG_VERSION");
        let metadata = format!("keyring-rs v{VERSION} for service '{service}', user '{user}'");
        let credential = if let Some(target) = target {
            // if target.is_empty() {
            //     return Err(ErrorCode::Invalid(
            //         "target".to_string(),
            //         "cannot be empty".to_string(),
            //     ));
            // }
            Self {
                // On Windows, the target name is all that's used to
                // search for the credential, so we allow clients to
                // specify it if they want a different convention.
                username: user.to_string(),
                target_name: target.to_string(),
                target_alias: String::new(),
                comment: metadata,
            }
        } else {
            Self {
                // Note: default concatenation of user and service name is
                // used because windows uses target_name as sole identifier.
                // See the module docs for more rationale.  Also see this issue
                // for Python: https://github.com/jaraco/keyring/issues/47
                //
                // Note that it's OK to have an empty user or service name,
                // because the format for the target name will not be empty.
                // But it's certainly not recommended.
                username: user.to_string(),
                target_name: format!("{user}.{service}"),
                target_alias: String::new(),
                comment: metadata,
            }
        };
        credential.validate_attributes("")?;
        Ok(credential)
    }
}

/// The builder for Windows Generic credentials.
pub struct WinCredentialBuilder {}

/// Returns an instance of the Windows credential builder.
///
/// On Windows,
/// this is called once when an entry is first created.
pub fn default_credential_builder() -> Box<CredentialBuilder> {
    Box::new(WinCredentialBuilder {})
}

impl CredentialBuilderApi for WinCredentialBuilder {
    /// Build a [WinCredential] for the given target, service, and user.
    fn build(&self, target: Option<&str>, service: &str, user: &str) -> Result<Box<Credential>> {
        Ok(Box::new(WinCredential::new_with_target(
            target, service, user,
        )?))
    }

    /// Return the underlying builder object with an `Any` type so that it can
    /// be downgraded to a [WinCredentialBuilder] for platform-specific processing.
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

fn extract_password(credential: &CREDENTIALW) -> Result<String> {
    // get password blob
    let blob_pointer: *const u8 = credential.CredentialBlob;
    let blob_len: usize = credential.CredentialBlobSize as usize;
    if blob_len == 0 {
        return Ok(String::new());
    }
    let blob = unsafe { std::slice::from_raw_parts(blob_pointer, blob_len) };
    // 3rd parties may write credential data with an odd number of bytes,
    // so we make sure that we don't try to decode those as utf16
    if blob.len() % 2 != 0 {
        let err = ErrorCode::BadEncoding(blob.to_vec());
        return Err(err);
    }
    // Now we know this _can_ be a UTF-16 string, so convert it to
    // as UTF-16 vector and then try to decode it.
    let mut blob_u16 = vec![0; blob.len() / 2];
    LittleEndian::read_u16_into(blob, &mut blob_u16);
    String::from_utf16(&blob_u16).map_err(|_| ErrorCode::BadEncoding(blob.to_vec()))
}

fn to_wstr(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(once(0)).collect()
}

fn to_wstr_no_null(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

unsafe fn from_wstr(ws: *const u16) -> String {
    // null pointer case, return empty string
    if ws.is_null() {
        return String::new();
    }
    // this code from https://stackoverflow.com/a/48587463/558006
    let len = (0..).take_while(|&i| *ws.offset(i) != 0).count();
    if len == 0 {
        return String::new();
    }
    let slice = std::slice::from_raw_parts(ws, len);
    String::from_utf16_lossy(slice)
}

pub fn entry_from_search(credential: &std::collections::HashMap<String, String>) -> Result<Entry> {
    let target = if let Some(target) = credential.get(&"Target".to_string()) {
        target
    } else {
        return Err(ErrorCode::Invalid(
            "get entry values Windows, target".to_string(),
            "No target key found in credential".to_string(),
        ));
    };
    let comment = if let Some(comment) = credential.get(&"Comment".to_string()) {
        comment
    } else {
        return Err(ErrorCode::Invalid(
            "get entry values Windows, service/comment".to_string(),
            "No comment key found in credential".to_string(),
        ));
    };
    let user = if let Some(user) = credential.get(&"User".to_string()) {
        user
    } else {
        return Err(ErrorCode::Invalid(
            "get entry values Windows, user".to_string(),
            "No user key found in credential".to_string(),
        ));
    };

    let wincredential = Box::new(WinCredential {
        username: user.to_string(),
        target_name: target.to_string(),
        target_alias: "".to_string(),
        comment: comment.to_string(),
    });

    Ok(Entry::new_with_credential(wincredential))
}

/// Windows error codes are `DWORDS` which are 32-bit unsigned ints.
#[derive(Debug)]
pub struct Error(pub u32);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.0 {
            ERROR_NO_SUCH_LOGON_SESSION => write!(f, "Windows ERROR_NO_SUCH_LOGON_SESSION"),
            ERROR_NOT_FOUND => write!(f, "Windows ERROR_NOT_FOUND"),
            ERROR_BAD_USERNAME => write!(f, "Windows ERROR_BAD_USERNAME"),
            ERROR_INVALID_FLAGS => write!(f, "Windows ERROR_INVALID_FLAGS"),
            ERROR_INVALID_PARAMETER => write!(f, "Windows ERROR_INVALID_PARAMETER"),
            err => write!(f, "Windows error code {err}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

/// Map the last encountered Windows API error to a crate error with appropriate annotation.
pub fn decode_error() -> ErrorCode {
    match unsafe { GetLastError() } {
        ERROR_NOT_FOUND => ErrorCode::NoEntry,
        ERROR_NO_SUCH_LOGON_SESSION => {
            ErrorCode::NoStorageAccess(wrap(ERROR_NO_SUCH_LOGON_SESSION))
        }
        err => ErrorCode::PlatformFailure(wrap(err)),
    }
}

fn wrap(code: u32) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(Error(code))
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use windows_sys::Win32::Foundation::SYSTEMTIME;
    use windows_sys::Win32::Storage::FileSystem::FileTimeToLocalFileTime;
    use windows_sys::Win32::System::Time::{LocalFileTimeToLocalSystemTime, TIME_ZONE_INFORMATION};

    use super::*;

    use crate::credential::CredentialPersistence;
    use crate::tests::{generate_random_string, generate_random_string_of_len};
    use crate::Entry;

    #[test]
    fn test_persistence() {
        assert!(matches!(
            default_credential_builder().persistence(),
            CredentialPersistence::UntilDelete
        ))
    }

    fn entry_new(service: &str, user: &str) -> Entry {
        crate::tests::entry_from_constructor(WinCredential::new_with_target, service, user)
    }

    #[test]
    fn test_bad_password() {
        fn make_platform_credential(password: &mut Vec<u8>) -> CREDENTIALW {
            let last_written = FILETIME {
                dwLowDateTime: 0,
                dwHighDateTime: 0,
            };
            let attribute_count = 0;
            let attributes: *mut CREDENTIAL_ATTRIBUTEW = std::ptr::null_mut();
            CREDENTIALW {
                Flags: 0,
                Type: CRED_TYPE_GENERIC,
                TargetName: std::ptr::null_mut(),
                Comment: std::ptr::null_mut(),
                LastWritten: last_written,
                CredentialBlobSize: password.len() as u32,
                CredentialBlob: password.as_mut_ptr(),
                Persist: CRED_PERSIST_ENTERPRISE,
                AttributeCount: attribute_count,
                Attributes: attributes,
                TargetAlias: std::ptr::null_mut(),
                UserName: std::ptr::null_mut(),
            }
        }
        // the first malformed sequence can't be UTF-16 because it has an odd number of bytes.
        // the second malformed sequence has a first surrogate marker (0xd800) without a matching
        // companion (it's taken from the String::fromUTF16 docs).
        let mut odd_bytes = b"1".to_vec();
        let malformed_utf16 = [0xD834, 0xDD1E, 0x006d, 0x0075, 0xD800, 0x0069, 0x0063];
        let mut malformed_bytes: Vec<u8> = vec![0; malformed_utf16.len() * 2];
        LittleEndian::write_u16_into(&malformed_utf16, &mut malformed_bytes);
        for bytes in [&mut odd_bytes, &mut malformed_bytes] {
            let credential = make_platform_credential(bytes);
            match extract_password(&credential) {
                Err(ErrorCode::BadEncoding(str)) => assert_eq!(&str, bytes),
                Err(other) => panic!("Bad password ({bytes:?}) decode gave wrong error: {other}"),
                Ok(s) => panic!("Bad password ({bytes:?}) decode gave results: {s:?}"),
            }
        }
    }

    #[test]
    fn test_validate_attributes() {
        fn validate_attribute_too_long(result: Result<()>, attr: &str, len: u32) {
            match result {
                Err(ErrorCode::TooLong(arg, val)) => {
                    assert_eq!(&arg, attr, "Error names wrong attribute");
                    assert_eq!(val, len, "Error names wrong limit");
                }
                Err(other) => panic!("Error is not '{attr} too long': {other}"),
                Ok(_) => panic!("No error when {attr} too long"),
            }
        }
        let cred = WinCredential {
            username: "username".to_string(),
            target_name: "target_name".to_string(),
            target_alias: "target_alias".to_string(),
            comment: "comment".to_string(),
        };
        for (attr, len) in [
            ("user", CRED_MAX_USERNAME_LENGTH),
            ("target", CRED_MAX_GENERIC_TARGET_NAME_LENGTH),
            ("target alias", CRED_MAX_STRING_LENGTH),
            ("comment", CRED_MAX_STRING_LENGTH),
            ("password", CRED_MAX_CREDENTIAL_BLOB_SIZE / 2),
        ] {
            let long_string = generate_random_string_of_len(1 + len as usize);
            let mut bad_cred = cred.clone();
            let mut password = "password";
            match attr {
                "user" => bad_cred.username = long_string.clone(),
                "target" => bad_cred.target_name = long_string.clone(),
                "target alias" => bad_cred.target_alias = long_string.clone(),
                "comment" => bad_cred.comment = long_string.clone(),
                "password" => password = &long_string,
                other => panic!("unexpected attribute: {other}"),
            }
            let expected_length = if attr == "password" { len * 2 } else { len };
            validate_attribute_too_long(
                bad_cred.validate_attributes(password),
                attr,
                expected_length,
            );
        }
    }

    #[test]
    fn test_password_valid_only_after_conversion_to_utf16() {
        let cred = WinCredential {
            username: "username".to_string(),
            target_name: "target_name".to_string(),
            target_alias: "target_alias".to_string(),
            comment: "comment".to_string(),
        };

        let len = CRED_MAX_CREDENTIAL_BLOB_SIZE / 2;
        let password: String = (0..len).map(|_| "笑").collect();

        assert!(password.len() > CRED_MAX_CREDENTIAL_BLOB_SIZE as usize);
        cred.validate_attributes(&password)
            .expect("Password of appropriate length in UTF16 was invalid");
    }

    #[test]
    fn test_invalid_parameter() {
        let credential = WinCredential::new_with_target(Some(""), "service", "user");
        assert!(
            matches!(credential, Err(ErrorCode::Invalid(_, _))),
            "Created entry with empty target"
        );
    }

    #[test]
    fn test_empty_service_and_user() {
        crate::tests::test_empty_service_and_user(entry_new);
    }

    #[test]
    fn test_missing_entry() {
        crate::tests::test_missing_entry(entry_new);
    }

    #[test]
    fn test_empty_password() {
        crate::tests::test_empty_password(entry_new);
    }

    #[test]
    fn test_round_trip_ascii_password() {
        crate::tests::test_round_trip_ascii_password(entry_new);
    }

    #[test]
    fn test_round_trip_non_ascii_password() {
        crate::tests::test_round_trip_non_ascii_password(entry_new);
    }

    #[test]
    fn test_update() {
        crate::tests::test_update(entry_new);
    }

    #[test]
    fn test_get_credential() {
        let name = generate_random_string();
        let entry = entry_new(&name, &name);
        let password = "test get password";
        entry
            .set_password(password)
            .expect("Can't set test get password");
        let credential: &WinCredential = entry
            .get_credential()
            .downcast_ref()
            .expect("Not a windows credential");
        let actual = credential.get_credential().expect("Can't read credential");
        assert_eq!(
            actual.username, credential.username,
            "Usernames don't match"
        );
        assert_eq!(
            actual.target_name, credential.target_name,
            "Target names don't match"
        );
        assert_eq!(
            actual.target_alias, credential.target_alias,
            "Target aliases don't match"
        );
        assert_eq!(actual.comment, credential.comment, "Comments don't match");
        entry
            .delete_password()
            .expect("Couldn't delete get-credential");
        assert!(matches!(entry.get_password(), Err(ErrorCode::NoEntry)));
    }

    unsafe fn get_last_written(last_written: FILETIME) -> String {
        static DAYS: [&str; 7] = [
            "Monday",
            "Tuesday",
            "Wednesday",
            "Thursday",
            "Friday",
            "Saturday",
            "Sunday",
        ];
        static MONTHS: [&str; 12] = [
            "January",
            "February",
            "March",
            "April",
            "May",
            "June",
            "July",
            "August",
            "September",
            "October",
            "November",
            "December",
        ];

        let mut local_filetime: FILETIME = std::mem::zeroed();
        let mut system_time: SYSTEMTIME = std::mem::zeroed();
        let local: TIME_ZONE_INFORMATION = std::mem::zeroed();
        FileTimeToLocalFileTime(&last_written, &mut local_filetime as *mut FILETIME);
        LocalFileTimeToLocalSystemTime(
            &local,
            &local_filetime,
            &mut system_time as *mut SYSTEMTIME,
        );

        let hour = system_time.wHour;
        let minute = system_time.wMinute;
        let second = system_time.wSecond;
        let day = system_time.wDay;
        let year = system_time.wYear;
        let month = system_time.wMonth;
        let day_of_week = system_time.wDayOfWeek;

        format!(
            "{}, {} {}, {} at {:02}:{:02}:{:02}",
            DAYS[day_of_week as usize - 1],
            day,
            MONTHS[month as usize - 1],
            year,
            hour,
            minute,
            second
        )
    }

    #[test]
    fn test_search() {
        let name = generate_random_string();
        let entry = Entry::new(&name, &name).expect("Failed to create entry");
        entry
            .set_password("password")
            .expect("Failed to set password for entry");

        let target = format!("{name}.{name}");

        let mut r_credential: *mut CREDENTIALW = std::ptr::null_mut();
        let last_written_filetime = unsafe {
            if CredReadW(
                to_wstr(&target).as_ptr(),
                CRED_TYPE_GENERIC,
                CRED_FLAGS::default(),
                &mut r_credential,
            ) == 0
            {
                panic!("Failed to read credential");
            };

            if r_credential.is_null() {
                panic!("r_credential is null");
            }

            let read_credential = *r_credential;
            CredFree(r_credential as *mut _);
            read_credential.LastWritten
        };

        let search_result = Entry::search(&name);
        let list = Entry::list_results(&search_result);

        let cred_type = "Generic";
        let persist = "Enterprise";
        const VERSION: &str = env!("CARGO_PKG_VERSION");
        let comment = format!("keyring-rs v{VERSION} for service '{name}', user '{name}'");

        let expected = format!(
            "1\nTarget: {}\nLast Written: {}\nType: {}\nPersist: {}\nUser: {}\nComment: {}\n",
            target,
            unsafe { get_last_written(last_written_filetime) },
            cred_type,
            persist,
            &name,
            comment
        );

        let expected: HashSet<&str> = expected.lines().collect();
        let result: HashSet<&str> = list.lines().collect();

        entry.delete_password().expect("Failed to delete password");

        assert_eq!(expected, result);
    }

    #[test]
    fn test_entry_from_search() {
        let name = generate_random_string();
        let password1 = "password1";
        let password2 = "password2";
        let entry = Entry::new_with_target(&name, "test-service", "test-user")
            .expect("Error creating new entry");
        entry
            .set_password(password1)
            .expect("error setting password1");

        let old_password = entry
            .get_password()
            .expect("failed to get password from old entry");
        let results = &Entry::search(&name);

        let result_entry =
            Entry::from_search_results(results, 1).expect("Failed to create entry from results");
        result_entry
            .set_password(password2)
            .expect("error setting password2");

        let new_password = result_entry
            .get_password()
            .expect("Failed to get password from new entry");

        assert_eq!(password1, old_password);
        assert_eq!(password2, new_password);

        result_entry
            .delete_password()
            .expect("Failed to delete new entry");
        let e = entry.delete_password().unwrap_err();

        assert!(matches!(e, ErrorCode::NoEntry));
    }
}
