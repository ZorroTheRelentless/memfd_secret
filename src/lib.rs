#![warn(missing_docs)]
#![allow(clippy::needless_doctest_main)]
//! The `memfd_secret` crate provides a convenient way to store and retrieve
//! sensitive data on Linux by wrapping the
//! [`memfd_secret`](https://www.man7.org/linux/man-pages//man2/memfd_secret.2.html)
//! syscall. The underlying memory is zeroed when the secret is dropped. This
//! crate has 100% unit test coverage, including property testing with
//! [`hegel`](https://docs.rs/hegeltest/latest/hegel/).
//!
//! #### Note
//! The `memfd_secret` syscall support starts from Linux version 5.14. Prior to
//! Linux 6.5 the admin must pass the `secretmem.enable=y` kernel parameter to
//! use this crate. See the
//! [manpages](https://www.man7.org/linux/man-pages//man2/memfd_secret.2.html)
//! for more information.
//!
//! Starting from Linux 6.5 `memfd_secret` is enabled by the kernel by default.
//!
//! # Quickstart
//! #### Store and Retrieve a String
//! ```
//! use memfd_secret::{MemfdSecret};
//! use std::io::{Read, Write};
//!
//! let secret = "my secret";
//!
//! // create a memfd secret of the appropriate size
//! let mut vault = MemfdSecret::new(secret.len()).unwrap();
//! // provide a byte slice of your data
//! vault.as_mut_slice().write_all(secret.as_bytes()).unwrap();
//!
//! // retrieve the data stored in the memfd secret
//! let mut vault_contents = String::new();
//! vault.as_slice().read_to_string(&mut vault_contents).unwrap();
//!
//! // enjoy
//! assert_eq!(vault_contents, secret)
//! ```
//!
//!
//! #### Store a secret from the command line using [clap](https://docs.rs/clap/latest/clap/index.html) and expose it safely
//! ```
//! // 1. Implement `std::str::FromStr` to use `clap::Parser`
//! use memfd_secret::MemfdSecret;
//! use std::io::{Read, Write};
//! use clap::Parser;
//!
//! // SecretString wraps memfd_secret to provide a convenient interface
//! #[derive(Debug, Clone)]
//! pub struct SecretString {
//!     secret: MemfdSecret,
//! }
//!
//! // the FromStr trait implementation allows clap to fill the secret
//! impl std::str::FromStr for SecretString {
//!     type Err = std::io::Error;
//!
//!     fn from_str(s: &str) -> Result<Self, Self::Err> {
//!         Self::new(s)
//!     }
//! }
//!
//! impl SecretString {
//!     pub fn new(s: &str) -> std::io::Result<SecretString> {
//!         let mut secret = MemfdSecret::new(s.len())?;
//!         secret.as_mut_slice().write_all(s.as_bytes()).unwrap();
//!         Ok(SecretString { secret })
//!     }
//!
//!         // the .expose() method returns the secret as a zeroizing string
//!         // the underlying memory is zeroed when the string is dropped
//!         // and the original copy is still in the `memfd_secret` vault.
//!     pub fn expose(&self) -> zeroize::Zeroizing<String> {
//!         let mut secret = zeroize::Zeroizing::new(String::new());
//!         self.secret.as_slice().read_to_string(&mut secret).unwrap();
//!         secret
//!    }
//!}
//!
//! // 2. Create and initialise an Args struct with the secret fields
//! #[derive(Parser, Debug)]
//! pub struct Args {
//!     #[clap(long, default_value = "abc")]
//!     pub api_key: SecretString,
//!     #[clap(long, default_value = "def")]
//!     pub secret_api_key: SecretString,
//! }
//! impl Args {
//!     pub fn new() -> Self {
//!         Self::parse()
//!     }
//! }
//!
//! fn main() {
//!     let args = Args::new();
//!     // 3. Expose the secret
//!     let actual_api_key = zeroize::Zeroizing::new(String::from("abc"));
//!     let expected_api_key = args.api_key.expose();
//!     assert_eq!(expected_api_key, actual_api_key);
//! }
//! ```

#[cfg(not(target_os = "linux"))]
compile_error!("memfd-secret is only supported on linux!");

mod memfd_secret;
pub use memfd_secret::{MemfdSecret, MemfdSecretBuilder, MemfdSecretFlags};
