## Version 2.0
- Introduce traits for pluggable store implementations.
- Add a `mock` store.

## Version 1.2
- introduce protection against the use of empty arguments

## Version 1.1.2
- replace `structopt` with new, improved `clap` that incorporates all of the same functionality.

## Version 1.1.1
- no functional updates, just documentation improvements

## Version 1.1.0
- add iOS support

## Version 1.0.1
- fix #80: missing winapi features (jyuch)

## Version 1.0.0
- Breaking API changes:
  - `Keyring` struct renamed to `Entry`
  - `KeyringError` enum renamed to `Error`, and is completely cross-platform.
- API enhancements:
  - Clients can now control how entries map to credentials; see `Entry::new_with_target` and `Entry::new_with_credential`
  - Clients can now retrieve platform credentials with metadata rather than just passwords; see `Entry::get_password_and_credential`.
  - Non UTF8 passwords now have their data available.
  - Non-login keychains are usable on Linux and Mac.
- Expanded documentation and `cli` example.

## Version 0.10.4
- CI fix for linux executable

## Version 0.10.3
- Added NoPassword and NoBackend errors to windows code (phillip couto)
- Update dependencies: (brotskydotcom)
    - secret-service from 1.1.1 to 2.0.2
    - security-framework from 0.4.2 to 2.4.2
- Update CI/tests, readme (brotskydotcom)

## Version 0.10.2
- yanked, release snafu

## Version 0.10.1
- update to secret-service 1.1.1

## Version 0.10.0
- ability to access named keychains in macos (nagasunilt)

## Version 0.9.0
- upgrade security-framework 0.3.0 -> 0.4.2
- upgrade secret-service 1.0.0 -> 1.1.0 (updates hkdf dep, fixes error handling related to missing collection)

## Version 0.8.0
- Upgrade to winapi 0.3 and removes advapi32-sys from windows.
- Upgrades to edition 2018
- Formats everything to 1.40
- Removes mem::uninitialized from windows.

## Version 0.7.1
- only include application name on create password, not on get password

## Version 0.7.0
- cli binary moved to examples.
- osx now uses `security-framework` library instead of cli.
- hex dependency removed on osx.
- update to `secret-service` for linux, which
  - removes gmp as a dependency
  - updates rust-crypto to RustCrypto
  - correctly encrypts/decrypts blank input
- tests moved to `lib.rs`

Plan to move to 1.0 if this version is stable.

## Version 0.6.1
- bug fix for special characters on osx.

## Version 0.6.0
- fix behavior in windows where third-party editing of password would result in malformed retrieved password. The solution was to convert all strings to and from Windows utf16, where before I was passing the secret as a blob from utf8.
- remove dependency on rustcserialize, use hex.
- update rpassword to 2.0, removing dependency on termios
- fix some mistakes in syntax for targeting dependencies to an os.

## Version 0.5.1
- remove some unwraps which were causing a problem in linux

## Version 0.5
- bumped secret-service to 0.4.0, which improved error-handling around emptyr passwords a bit more (in 0.3.1), and made gmp dependency optional in 0.4.0

## Version 0.4
- yanked. But originally was trying to handle secret-service empty password better. But there was an error in secret-service 0.3

## Version 0.3
- Windows support!

## Version 0.2

- Fix major bug in decoding output on osx. Now handles both regular and "special" (non-ascii) utf8 chars appropriately.
- add simple tests for the fix!
- add changelog.

## Version 0.1

- linux implementation using secret-service backend.
- osx implementation using security cli.
