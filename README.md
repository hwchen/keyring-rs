## Keyring-rs

A cross-platorm library and utility to manage passwords.

## Usage

__Currently supports Linux, macOS, and Windows.__ Please file issues if you have any problems or bugs!

To use this library in your project add the following to your `Cargo.toml` file:

```Rust
[dependencies]
keyring = "0.3.0"
```

This will give you access to the `keyring` crate in your code. Now you can use
the `new` function to get an instance of the `Keyring` struct. The `new`
function expects a `service` name and an `username` with which it accesses
the password.

You can get a password from the OS keyring with the `get_password` function.

```Rust
extern crate keyring;

fn main() {
  let service = "my_application_name";
  let username = "username";

  let keyring = keyring::Keyring::new(&service, &username)

  let password = keyring.get_password().unwrap()
  println!("The password is '{}'", password);
}
```

Passwords can also be added to the keyring using the `set_password` function.

```Rust
extern crate keyring;

fn main() {
  let service = "my_application_name";
  let username = "username";

  let keyring = keyring::Keyring::new(&service, &username)

  let password = "topS3cr3tP4$$w0rd";
  keyring.set_password(&password).unwrap();

  let password = keyring.get_password().unwrap()
  println!("The password is '{}'", password);
}
```

And they can be deleted with the `delete_password` function.

```Rust
extern crate keyring;

fn main() {
  let service = "my_application_name";
  let username = "username";

  let keyring = keyring::Keyring::new(&service, &username)

  keyring.delete_password().unwrap();

  println!("The password s been deleted");
}
```

## Errors

The `get_password`, `set_password` and `delete_password` functions return a
`Result` which, if the operation was unsuccessful, can yield a `KeyringError`.

The `KeyringError` struct implements the `error::Error` and `fmt::Display`
traits, so it can be queried for a cause and an description using methods of
the same name.

## Caveats

### macOS

* Special characters support is experimental.
Please file an issue if this gives you trouble.

### Linux

* The application name is hardcoded to be `rust-keyring`.

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

