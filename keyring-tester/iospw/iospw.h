/// Header material that XCode can use to create a bridging header
///
/// In order to call the external C ABI from Swift, XCode creates a
/// "bridging header" in which it does memory reference analysis of
/// the C API entires.  The default analysis is that input-only objects
/// remain memory managed, but in-out objects are unmanaged.
///
/// In this API, there is one call - `KeyringCopyGenericPassword` - that
/// retains an output CFData object and passes ownership to the caller.
/// Although it's named correctly per CF conventions to let the compiler
/// infer that the output is retained, that's not always reliably done,
/// so in this header the CF_RETURNS_RETAINED annotation is used to force
/// the correct interpretation.  This allows Swift (and other ARC-based)
/// callers to do automated memory management.
#ifndef RUST_SECURITY_FRAMEWORK_IOSPW_H
#define RUST_SECURITY_FRAMEWORK_IOSPW_H

#include <CoreFoundation/CoreFoundation.h>

/// Set a generic password for the given service and account.
/// Creates or updates a keychain entry.
/// If an unexpected runtime error is encountered, the status will be `errSecParam`.
extern OSStatus KeyringSetPassword(CFStringRef service, CFStringRef account, CFStringRef password);

/// Get the password for the given service and account.  If no keychain entry
/// exists for the service and account, returns `errSecItemNotFound`.
/// If the password is not UTF8-encoded, the status will be `errSecDecode`.
/// If an unexpected runtime error is encountered, the status will be `errSecParam`.
///
/// # Safety
/// The `password` argument to this function is a mutable pointer to a CFStringRef.
/// This is an input-output variable, and (as per CF standards) should come in
/// either as nil (a null pointer) or as the address of a CFStringRef whose value is nil.
/// If the input passowrd value is nil, then the password will be looked up
/// and an appropriate status returned, but the password data will not be output.
/// If the input value is non-nil, then the password will be looked up and,
/// if found:
///     1. a new CFData item will be allocated and retained,
///     2. a copy of the password's bytes will be put into the CFData item, and
///     3. the CFStringRef will be reset to refer to the allocated, retained item.
/// Note that the current value of the CFStringRef on input will not be freed, so
/// if you pass in a CFStringRef address to receive the password the input value
/// of that pointed-to CFStringRef must be nil.
extern OSStatus KeyringCopyPassword(CFStringRef service, CFStringRef account, CF_RETURNS_RETAINED CFStringRef *password);

/// Delete the keychain entry for the given service and account.  If none
/// exists, returns `errSecItemNotFound`.
/// If an unexpected runtime error is encountered, the status will be `errSecParam`.
extern OSStatus KeyringDeletePassword(CFStringRef service, CFStringRef account);

#endif //RUST_SECURITY_FRAMEWORK_IOSPW_H
