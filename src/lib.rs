#![warn(missing_docs)]
//! The memfd_secret crate provides a convenient way to store and retrieve sensitive data on Linux by wrapping the [memfd_secret](https://www.man7.org/linux/man-pages//man2/memfd_secret.2.html) syscall. Memory is zeroed when the secret is dropped.
//! #### Note
//! The memfd_secret syscall support starts from Linux version 5.14. Prior to Linux 6.5 the admin must pass the `secretmem.enable=y` kernel parameter to use this crate. See the [manpages](https://www.man7.org/linux/man-pages//man2/memfd_secret.2.html) for more information.
//!
//! Starting from Linux 6.5 memfd_secret is enabled by the kernel by default.
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
//! #### Use Deref behaviour to access and modify secret
#[cfg(not(target_os = "linux"))]
compile_error!("memfd-secret is only supported on linux!");

use std::os::fd::FromRawFd;

/// Struct that represents information required to manage a memfd secret
#[derive(Debug)]
pub struct MemfdSecret {
    /// file is not used directly, but needs to be held to ensure the mmap remains alive.
    _file: std::fs::File,
    size: usize,
    ptr: std::ptr::NonNull<libc::c_void>,
}
impl MemfdSecret {
    /// Create a new `MemfdSecret` with the given size. Use `new()` when a standard memfd_secret is needed.
    /// ```
    /// # use memfd_secret::{MemfdSecret};
    /// let vault = MemfdSecret::new(1024).unwrap();
    /// ```
    pub fn new(size: usize) -> std::io::Result<Self> {
        MemfdSecret::builder().build(size)
    }

    /// Use `builder()` when a non-default `flag` is required.
    /// ```
    /// // *cloexec: false* allows a subprocess access
    /// # use memfd_secret::{MemfdSecret, MemfdSecretFlags};
    /// let mut vault = MemfdSecret::builder()
    ///    .with_flags(MemfdSecretFlags { cloexec: false })
    ///    .build(1)
    ///    .unwrap();
    /// vault[0] = 1;
    /// assert_eq!(vault[0], 1);
    /// ```
    pub fn builder() -> MemfdSecretBuilder {
        MemfdSecretBuilder::new()
    }

    /// Returns a **read only** byte slice, see quickstart for a complete example.
    /// ```
    /// # use memfd_secret::{MemfdSecret};
    /// # let secret = "my secret";
    /// # let mut vault = MemfdSecret::new(secret.len()).unwrap();
    /// let byte_slice = vault.as_slice();
    /// ```
    /// Alternatively use the Deref trait implemented for MemfdSecret to access the data using the same underlying function.
    /// ```
    /// # use memfd_secret::{MemfdSecret};
    /// # let secret = "my secret";
    /// # let mut vault = MemfdSecret::new(secret.len()).unwrap();
    /// let byte_slice: &[u8] = &vault[..];
    /// ```
    pub fn as_slice(&self) -> &[u8] {
        // the pointer is cast as a const u8 rather than a mut u8 to allow safe access from std::ops::Deref
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr() as *const u8, self.size) }
    }
    /// Returns a **modifiable** byte slice, see the quickstart for a complete example
    /// ```
    /// # use memfd_secret::{MemfdSecret};
    /// # let secret = "my secret";
    /// # let mut vault = MemfdSecret::new(secret.len()).unwrap();
    /// let mut byte_slice = vault.as_slice();
    /// ```
    /// Alternatively use the Deref trait implemented for MemfdSecret to access the data using the same underlying function.
    /// ```
    /// # use memfd_secret::{MemfdSecret};
    /// # let secret = "my secret";
    /// # let mut vault = MemfdSecret::new(secret.len()).unwrap();
    /// let mut byte_slice: &[u8] = &vault[..];
    /// ```
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr() as *mut u8, self.size) }
    }
}
impl Drop for MemfdSecret {
    fn drop(&mut self) {
        unsafe {
            self.ptr.write_bytes(0, self.size);
        }

        let result = unsafe { libc::munmap(self.ptr.as_ptr(), self.size) };
        if result != 0 {
            panic!("munmap failed with code: {}", result);
        }
    }
}
impl std::ops::Deref for MemfdSecret {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}
impl std::ops::DerefMut for MemfdSecret {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_slice()
    }
}

#[derive(Debug)]
/// Valid flag/s for memfd_secret.
/// Currently the syscall memfd_secret only accepts one flag.
// Struct is more for organised and for future use in case new flags are added for memfd_secret.
pub struct MemfdSecretFlags {
    /// `libc::O_CLOEXEC` prevents sub-processes from accessing the file.
    /// **Default: false**
    pub cloexec: bool,
}

/// Builder options are already exposed through MemfdSecret.
pub struct MemfdSecretBuilder {
    flags: MemfdSecretFlags,
}
impl Default for MemfdSecretBuilder {
    fn default() -> Self {
        Self {
            flags: MemfdSecretFlags { cloexec: true },
        }
    }
}
impl MemfdSecretBuilder {
    /// Creates new MemfdSecretBuilder with defaults.
    pub fn new() -> Self {
        Self::default()
    }
    /// Passes flags with MemfdSecretBuilder.
    pub fn with_flags(mut self, flags: MemfdSecretFlags) -> Self {
        self.flags = flags;
        self
    }
    /// Builds MemfdSecret with passed parameters.
    pub fn build(self, size: usize) -> std::io::Result<MemfdSecret> {
        memfd_secret(&self.flags, size)
    }
}

fn memfd_secret(flags: &MemfdSecretFlags, size: usize) -> std::io::Result<MemfdSecret> {
    // flag to memfd secret libc::O_CLOEXEC, prevents sub-processed from accessing the file.
    // pass setting through struct
    let flags = if flags.cloexec { libc::O_CLOEXEC } else { 0 };
    let fd = unsafe { libc::syscall(libc::SYS_memfd_secret, flags) };
    mmap_secret(fd, size)
}

fn mmap_secret(fd: i64, size: usize) -> std::io::Result<MemfdSecret> {
    if fd < 0 {
        //Error case
        let os_error = std::io::Error::last_os_error();
        Err(os_error)
    } else {
        let file = unsafe { std::fs::File::from_raw_fd(fd as i32) };
        file.set_len(size as u64)?;
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED_VALIDATE,
                fd as i32,
                0,
            )
        };
        std::ptr::NonNull::new(ptr)
            .ok_or(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "mmap returned a null pointer",
            ))
            .map(|ptr| MemfdSecret {
                _file: file,
                size,
                ptr,
            })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    fn string_sample() -> (MemfdSecret, String) {
        let secret = "le secret";
        let mut vault = MemfdSecret::new(secret.len()).unwrap();
        vault.as_mut_slice().write_all(secret.as_bytes()).unwrap();
        (vault, String::from(secret))
    }
    #[test]
    fn write_retrieve() {
        let (vault, secret) = string_sample();
        let mut read_string = String::new();
        vault.as_slice().read_to_string(&mut read_string).unwrap();
        assert_eq!(read_string, secret);
    }
    #[test]
    #[should_panic]
    fn munmap_panic() {
        let mut vault = MemfdSecret::new(10).unwrap();
        vault.size = 0;
    }
    #[test]
    fn deref() {
        let (vault, secret) = string_sample();
        assert_eq!(vault[0], secret.as_bytes()[0]);
    }
    #[test]
    fn deref_mut() {
        let (mut vault, _) = string_sample();
        vault[0] = 10;
        assert_eq!(vault[0], 10);
    }
    #[test]
    fn with_flag_cloexec() {
        let mut vault = MemfdSecret::builder()
            .with_flags(MemfdSecretFlags { cloexec: false })
            .build(1)
            .unwrap();
        vault[0] = 1;
        assert_eq!(vault[0], 1);
    }
    //TODO create a test case to actually test the cloexec flag by spawning a child process.
    // #[test]
    // fn sub_process_access_with_cloexec() {
    //     //let (vault, _) = string_sample();
    // }
    #[test]
    fn memfd_secret_error() {
        // sets a global error
        errno::set_errno(errno::Errno(libc::EINVAL));
        let actual = mmap_secret(-1, 1).unwrap_err();
        // tests if mmap_secret returned the global error
        assert_eq!(actual.kind(), std::io::ErrorKind::InvalidInput)
    }
    // this tests probably hits the rlimit
    #[test]
    fn out_of_bounds_file_size() {
        let actual = MemfdSecret::new(usize::MAX).unwrap_err();
        assert_eq!(actual.kind(), std::io::ErrorKind::InvalidInput)
    }
}
#[cfg(test)]
mod property_tests {
    use super::*;
    use hegel::TestCase;
    use hegel::generators as gs;
    use std::io::Write;
    #[hegel::test]
    fn write_retrieve(tc: TestCase) {
        let secret = tc.draw(gs::binary().min_size(1));
        let mut vault = MemfdSecret::new(secret.len()).unwrap();
        vault.as_mut_slice().write_all(&secret).unwrap();
        assert_eq!(secret, vault[..]);
    }
}
