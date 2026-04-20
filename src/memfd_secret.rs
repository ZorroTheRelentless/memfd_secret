use std::{io::Write, os::fd::FromRawFd};

/// Struct that represents information required to manage a memfd secret
#[derive(Debug)]
pub struct MemfdSecret {
    // file is not used directly, but needs to be held to ensure the mmap remains alive.
    _file: std::fs::File,
    memmap: memmap2::MmapMut,
    flags: MemfdSecretFlags,
}

// Clone implemented to satisfy Clap's requirement.
impl std::clone::Clone for MemfdSecret {
    fn clone(&self) -> Self {
        let mut result = Self::builder()
            .with_flags(self.flags)
            .build(self.len())
            .unwrap();
        (&mut *result).write_all(self).unwrap();
        result
    }
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
    ///    .with_flags(MemfdSecretFlags::new().with_cloexec(false))
    ///    .build(1)
    ///    .unwrap();
    /// vault[0] = 1;
    /// assert_eq!(vault[0], 1);
    /// ```
    pub fn builder() -> MemfdSecretBuilder {
        MemfdSecretBuilder::new()
    }

    /// Returns a **read only** byte slice.
    /// ```
    /// # use memfd_secret::{MemfdSecret};
    /// # let secret = "my secret";
    /// # let mut vault = MemfdSecret::new(secret.len()).unwrap();
    /// let byte_slice = vault.as_slice();
    /// ```
    /// Alternatively use the [`Deref`](`std::ops::Deref`) trait implemented for MemfdSecret to access
    /// the data using the same underlying function.
    /// ```
    /// # use memfd_secret::{MemfdSecret};
    /// # let secret = "my secret";
    /// # let mut vault = MemfdSecret::new(secret.len()).unwrap();
    /// let byte_slice: &[u8] = &vault[..];
    /// ```
    pub fn as_slice(&self) -> &[u8] {
        &self.memmap
    }
    /// Returns a **modifiable** byte slice
    /// ```
    /// # use memfd_secret::{MemfdSecret};
    /// # let secret = "my secret";
    /// # let mut vault = MemfdSecret::new(secret.len()).unwrap();
    /// let mut byte_slice = vault.as_slice();
    /// ```
    /// Alternatively use the [`Deref`](`std::ops::Deref`) trait implemented for MemfdSecret to access
    /// the data using the same underlying function.
    /// ```
    /// # use memfd_secret::{MemfdSecret};
    /// # let secret = "my secret";
    /// # let mut vault = MemfdSecret::new(secret.len()).unwrap();
    /// let mut byte_slice: &[u8] = &vault[..];
    /// ```
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.memmap
    }
}
impl Drop for MemfdSecret {
    fn drop(&mut self) {
        // Zero the secret memory on drop.
        self.memmap.fill(0);
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

#[derive(Debug, Copy, Clone)]
/// Flags for configuring the [`MemfdSecret`] syscall.
///
/// Currently the syscall memfd_secret only accepts one flag.
// Struct is more for organised and for future use in case new flags are added for memfd_secret.
#[non_exhaustive]
pub struct MemfdSecretFlags {
    /// This maps to `libc::O_CLOEXEC` prevents sub-processes from accessing the file.
    pub cloexec: bool,
}

impl MemfdSecretFlags {
    /// Creates new MemfdSecretFlags with defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the `cloexec` flag.
    pub fn with_cloexec(mut self, cloexec: bool) -> Self {
        self.cloexec = cloexec;
        self
    }
}

impl Default for MemfdSecretFlags {
    fn default() -> Self {
        Self { cloexec: true }
    }
}

#[derive(Default)]
/// Builder options are already exposed through MemfdSecret.
pub struct MemfdSecretBuilder {
    flags: MemfdSecretFlags,
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
        memfd_secret(self.flags, size)
    }
}

fn memfd_secret(flags: MemfdSecretFlags, size: usize) -> std::io::Result<MemfdSecret> {
    // flag to memfd secret libc::O_CLOEXEC, prevents sub-processed from accessing the file.
    // pass setting through struct
    let fd = {
        let flags = if flags.cloexec { libc::O_CLOEXEC } else { 0 };
        unsafe { libc::syscall(libc::SYS_memfd_secret, flags) }
    };
    mmap_secret(fd, size, flags)
}

fn mmap_secret(fd: i64, size: usize, flags: MemfdSecretFlags) -> std::io::Result<MemfdSecret> {
    if fd < 0 {
        //Error case
        let os_error = std::io::Error::last_os_error();
        Err(os_error)
    } else {
        let file = unsafe { std::fs::File::from_raw_fd(fd as i32) };
        file.set_len(size as u64)?;
        unsafe { memmap2::MmapOptions::new().len(size).map_mut(&file) }.map(|memmap| MemfdSecret {
            _file: file,
            memmap,
            flags,
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
    fn deref() {
        let (vault, secret) = string_sample();
        assert_eq!(vault[..], secret.as_bytes()[..]);
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
    #[test]
    fn clone() {
        let (vault, secret) = string_sample();
        let cloned = vault.clone();
        assert_eq!(vault[..], cloned[..]);
        assert_eq!(cloned[..], secret.as_bytes()[..]);
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
        let actual = mmap_secret(-1, 1, Default::default()).unwrap_err();
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
