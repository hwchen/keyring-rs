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
#ifndef KEYRING_IOSPW_H
#define KEYRING_IOSPW_H

#include <CoreFoundation/CoreFoundation.h>

/// Set a generic password for the given service and account.
/// Creates or updates a keychain entry.
/// Otherwise, an appropriate error status is returned.
extern OSStatus KeyringSetPassword(CFStringRef service, CFStringRef account, CFStringRef password);

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
extern OSStatus KeyringCopyPassword(CFStringRef service, CFStringRef account, CF_RETURNS_RETAINED CFDataRef *password);

/// Delete the keychain entry for the given service and account.  If none
/// exists, returns `errSecItemNotFound`.
/// Otherwise, an appropriate error status is returned.
extern OSStatus KeyringDeletePassword(CFStringRef service, CFStringRef account);

#endif //KEYRING_IOSPW_H
