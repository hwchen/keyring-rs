/*!

# Platorm-independent secure storage model

This module defines a plug and play model for platform-specific credential stores.
The model comprises two traits: [CredentialBuilderApi] for the underlying store
and [CredentialApi] for the entries in the store.  These traits must be implemented
in a thread-safe way, a requirement captured in the [CredentialBuilder] and
[Credential] types that wrap them.

Note that you must have an instance of a credential builder in
your hands in order to call the [CredentialBuilder] API.  Because each credential
builder implementation lives in a platform-specific module, the cross-platform way to
get your hands on the one currently being used to create entries is to ask
for the builder from the `default` module alias.  For example, to
determine whether the credential builder currently being used
persists its credentials across machine reboots, you might use a snippet like this:

```rust
use keyring::{default, credential};

let persistence = default::default_credential_builder().persistence();
if  matches!(persistence, credential::CredentialPersistence::UntilDelete) {
    println!("The default credential builder persists credentials on disk!")
} else {
    println!("The default credential builder doesn't persist credentials on disk!")
}
```
 */
use std::any::Any;
use std::collections::HashMap;

use super::Result;

/// The API that [credentials](Credential) implement.
pub trait CredentialApi {
    /// Set the credential's password (a string).
    ///
    /// This will persist the password in the underlying store.
    fn set_password(&self, password: &str) -> Result<()>;

    /// Set the credential's secret (a byte array).
    ///
    /// This will persist the secret in the underlying store.
    fn set_secret(&self, password: &[u8]) -> Result<()>;

    /// Retrieve a password (a string) from the credential, if one has been set.
    ///
    /// This has no effect on the underlying store.
    fn get_password(&self) -> Result<String>;

    /// Retrieve a secret (a byte array) from the credential, if one has been set.
    ///
    /// This has no effect on the underlying store.
    fn get_secret(&self) -> Result<Vec<u8>>;

    /// Get the attributes on this credential from the underlying credential store.
    ///
    /// Almost all credential stores allow assigning named attributes to credentials.
    /// Which attributes are allowed by which stores varies widely.
    ///
    /// The attributes returned by this call
    /// include any that are used by this crate to identify
    /// the `target`, `service`, and `user` of the credential.
    /// The attributes used may not have those names; see the documentation
    /// of each credential store for details of which attributes are used
    /// and which additional attributes are returned by this call.
    fn get_attributes(&self) -> Result<HashMap<String, String>>;

    /// Delete the underlying credential, if there is one.
    ///
    /// This is not idempotent if the credential existed!
    /// A second call to delete_credential will return
    /// a [NoEntry](crate::Error::NoEntry) error.
    fn delete_credential(&self) -> Result<()>;

    /// Return the underlying concrete object cast to [Any].
    ///
    /// This allows clients
    /// to downcast the credential to its concrete type so they
    /// can do platform-specific things with it (e.g.,
    /// query its attributes in the underlying store).
    fn as_any(&self) -> &dyn Any;

    /// The Debug trait call for the object.
    ///
    /// This is used to implement the Debug trait on this type; it
    /// allows generic code to provide debug printing as provided by
    /// the underlying concrete object.
    ///
    /// We provide a (useless) default implementation for backward
    /// compatibility with existing implementors who may have not
    /// implemented the Debug trait for their credential objects
    fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self.as_any(), f)
    }
}

/// A thread-safe implementation of the [Credential API](CredentialApi).
pub type Credential = dyn CredentialApi + Send + Sync;

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.debug_fmt(f)
    }
}

/// A descriptor for the lifetime of stored credentials, returned from
/// a credential store's [persistence](CredentialBuilderApi::persistence) call.
#[non_exhaustive]
pub enum CredentialPersistence {
    /// Credentials vanish when the entry vanishes (stored in the entry)
    EntryOnly,
    /// Credentials vanish when the process terminates (stored in process memory)
    ProcessOnly,
    /// Credentials persist until the machine reboots (stored in kernel memory)
    UntilReboot,
    /// Credentials persist until they are explicitly deleted (stored on disk)
    UntilDelete,
}

/// The API that [credential builders](CredentialBuilder) implement.
pub trait CredentialBuilderApi {
    /// Create a credential identified by the given target, service, and user.
    ///
    /// This typically has no effect on the content of the underlying store.
    /// A credential need not be persisted until its password is set.
    fn build(&self, target: Option<&str>, service: &str, user: &str) -> Result<Box<Credential>>;

    /// Create a credential with additional platform-specific attributes.
    ///
    /// Almost all credential stores allow assigning named attributes to credentials.
    /// In order to improve interoperability with 3rd-party software, you can
    /// specify the desired values for attributes other than the ones that
    /// are used by this crate to identify the `target`, `service`, and `user`
    /// values of the credential.
    ///
    /// The attributes specified in this call are only applied when the credential
    /// is first created in the underlying store, which is when the very first
    /// secret value is assigned to the credential.  If a credential already exists
    /// with the `target`, `service`, and `user` values specified in this call,
    /// any additional attributes specified in it will be ignored.
    ///
    /// You can use the [CredentialApi::get_attributes] call to find out what
    /// additional attributes are present on an existing credential. If you wish to
    /// change those attributes, you will need to delete the existing credential,
    /// then specify those attributes in this call, and the set a secret to create
    /// the new credential with those attributes.
    ///
    /// Note that credential stores vary widely in what attributes they
    /// allow and which are used by this crate.  The documentation of the
    /// credential store implementations in this crate identify both
    /// which attributes they use and which others can be set.
    fn build_with_attributes(
        &self,
        target: Option<&str>,
        service: &str,
        user: &str,
        attributes: HashMap<&str, &str>,
    ) -> Result<Box<Credential>>;

    /// Return the underlying concrete object cast to [Any].
    ///
    /// Because credential builders need not have any internal structure,
    /// this call is not so much for clients
    /// as it is to allow automatic derivation of a Debug trait for builders.
    fn as_any(&self) -> &dyn Any;

    /// The lifetime of credentials produced by this builder.
    ///
    /// A default implementation is provided for backward compatibility,
    /// since this API was added in a minor release.  The default assumes
    /// that keystores use disk-based credential storage.
    fn persistence(&self) -> CredentialPersistence {
        CredentialPersistence::UntilDelete
    }
}

impl std::fmt::Debug for CredentialBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_any().fmt(f)
    }
}

/// A thread-safe implementation of the [CredentialBuilder API](CredentialBuilderApi).
pub type CredentialBuilder = dyn CredentialBuilderApi + Send + Sync;
