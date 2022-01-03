//! A C-ABI for the Rust `keyring` crate callable from iOS code.
//!
//! In order to embed Rust code in an iOS application, you must provide
//! a C-ABI wrapper that can be called into from Objective C or Swift.
//! This wrapper provides that for the password entries in
//! the keyring crate.
//!
//! Since the Core Foundation provides a C-ABI mechanism for using
//! Objective-C memory management, including ARC, and since the
//! keychain API involves transferring objects from the system
//! to the user process, this API uses CF objects for its parameters
//! rather than pure C strings and arrays.
//!
//! There is an accompanying header `iospw.h` in this directory
//! that provides Objective-C annotations for these functions
//! which are needed by the C compiler.
//!
//! For a good overview of the process by which Rust is embedded in
//! an iOS application, see
//! [this article](https://mozilla.github.io/firefox-browser-architecture/experiments/2017-09-06-rust-on-ios.html),
//! but be aware that it was written long enough ago that some of the processor
//! architectures it refers to are no longer in use.
use core_foundation::base::{CFRetain, OSStatus, TCFType};
use core_foundation::data::{CFData, CFDataRef};
use core_foundation::string::{CFString, CFStringRef};

extern crate keyring;
use keyring::{Entry, Error};

#[allow(non_upper_case_globals)]
pub const errSecSuccess: OSStatus = 0;
#[allow(non_upper_case_globals)]
pub const errSecParam: OSStatus = -50;
#[allow(non_upper_case_globals)]
pub const errSecBadReq: OSStatus = -909;
#[allow(non_upper_case_globals)]
const errSecDecode: OSStatus = -26275;
#[allow(non_upper_case_globals)]
const errSecItemNotFound: OSStatus = -25300;

/// Set a generic password for the given service and account.
/// Creates or updates a keychain entry.
/// Otherwise, an appropriate error status is returned.
#[no_mangle]
pub extern "C" fn KeyringSetPassword(
    service: CFStringRef,
    user: CFStringRef,
    password: CFStringRef,
) -> OSStatus {
    if service.is_null() || user.is_null() || password.is_null() {
        return errSecParam;
    }
    let service = unsafe { CFString::wrap_under_get_rule(service) }.to_string();
    let account = unsafe { CFString::wrap_under_get_rule(user) }.to_string();
    let password = unsafe { CFString::wrap_under_get_rule(password) }.to_string();
    let entry = Entry::new(&service, &account);
    match entry.set_password(&password) {
        Ok(_) => errSecSuccess,
        Err(Error::PlatformFailure(err)) => err.code(),
        Err(Error::NoStorageAccess(err)) => err.code(),
        Err(_) => errSecBadReq,
    }
}

/// Get the password for the given service and account.  If a password is
/// found, the status will either be `errSecSuccess` or `errSecDecode`
/// (meaning that it's not UTF8 encoded), and the password will be
/// returned.
/// If no keychain entry exists, returns `errSecItemNotFound`.
/// Otherwise, returns an appropriate error status (with no password).
///
///
/// # Safety
/// The `password` argument to this function is a mutable pointer to a CFDataRef.
/// (It's a DataRef not a StringRef because we have to be able to pass back badly
/// encoded passwords through the interface, rather than throw them.)
/// This DataRef is an input-output variable, and (as per CF standards) should come in
/// either as nil (a null pointer) or as the address of a CFDataRef whose value is nil.
/// If the input password value is nil, then the password will be looked up
/// and an appropriate status returned, but the password data will not be output.
/// If the input value is non-nil, then the password will be looked up and,
/// if found:
///     1. a new CFData item will be allocated and retained,
///     2. a copy of the password's bytes will be put into the CFData item, and
///     3. the CFDataRef will be reset to refer to the allocated, retained item.
/// Note that the current value of the CFDataRef on input will not be freed, so
/// if you pass in a CFDataRef address to receive the password the input value
/// of that pointed-to CFDataRef must be nil.
#[no_mangle]
pub unsafe extern "C" fn KeyringCopyPassword(
    service: CFStringRef,
    user: CFStringRef,
    password: *mut CFDataRef,
) -> OSStatus {
    if service.is_null() || user.is_null() {
        return errSecBadReq;
    }
    let service = CFString::wrap_under_get_rule(service).to_string();
    let account = CFString::wrap_under_get_rule(user).to_string();
    let entry = Entry::new(&service, &account);
    let copy_password_to_output = |bytes: &[u8]| {
        let data = CFData::from_buffer(bytes);
        // take an extra retain count to hand to our caller
        CFRetain(data.as_CFTypeRef());
        *password = data.as_concrete_TypeRef();
    };
    match entry.get_password() {
        Ok(string) => {
            if !password.is_null() {
                copy_password_to_output(string.as_bytes());
            }
            errSecSuccess
        }
        Err(Error::NoEntry) => errSecItemNotFound,
        Err(Error::PlatformFailure(err)) => err.code(),
        Err(Error::NoStorageAccess(err)) => err.code(),
        Err(Error::BadEncoding(bytes)) => {
            if !password.is_null() {
                copy_password_to_output(&bytes);
            }
            errSecDecode
        }
        Err(_) => errSecBadReq,
    }
}

/// Delete the keychain entry for the given service and account.  If none
/// exists, returns `errSecItemNotFound`.
/// Otherwise, an appropriate error status is returned.
#[no_mangle]
pub extern "C" fn KeyringDeletePassword(service: CFStringRef, user: CFStringRef) -> OSStatus {
    if service.is_null() || user.is_null() {
        return errSecParam;
    }
    let service = unsafe { CFString::wrap_under_get_rule(service) }.to_string();
    let account = unsafe { CFString::wrap_under_get_rule(user) }.to_string();
    let entry = Entry::new(&service, &account);
    match entry.delete_password() {
        Ok(_) => errSecSuccess,
        Err(Error::NoEntry) => errSecItemNotFound,
        Err(Error::PlatformFailure(err)) => err.code(),
        Err(Error::NoStorageAccess(err)) => err.code(),
        Err(_) => errSecBadReq,
    }
}
