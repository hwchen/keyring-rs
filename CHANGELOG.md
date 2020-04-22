## Verion 0.9.0
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
