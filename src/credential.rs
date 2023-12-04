/*!

# Platorm-independent secure storage model

This module defines a plug and play model for platform-specific credential stores.
The model comprises two traits: [CredentialBuilderApi] for the underlying store
and [CredentialApi] for the entries in the store.  These traits must be implemented
in a thread-safe way, a requirement captured in the [CredentialBuilder] and
[CredentialApi] types that wrap them.
 */
use super::Result;
use std::any::Any;

/// The API that [credentials](Credential) implement.
pub trait CredentialApi {
    /// Set the credential's password.
    ///
    /// This will persist the password in the underlying store.
    fn set_password(&self, password: &str) -> Result<()>;
    /// Retrieve a password from the credential, if one has been set.
    ///
    /// This has no effect on the underlying store.
    fn get_password(&self) -> Result<String>;
    /// Forget the credential's password, if one has been set.
    ///
    /// This will also remove the credential from the underlying store,
    /// so a second call to delete_password will return
    /// a [NoEntry](crate::Error::NoEntry) error.
    fn delete_password(&self) -> Result<()>;
    /// Return the underlying concrete object cast to [Any].
    ///
    /// This allows clients
    /// to downcast the credential to its concrete type so they
    /// can do platform-specific things with it (e.g.,
    /// query its attributes in the underlying store).
    fn as_any(&self) -> &dyn Any;
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_any().fmt(f)
    }
}

/// A thread-safe implementation of the [Credential API](CredentialApi).
pub type Credential = dyn CredentialApi + Send + Sync;

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
