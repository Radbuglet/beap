use std::{
    error::Error,
    ffi::CStr,
    fmt,
    ptr::{null_mut, NonNull},
};

use crate::page_size;

#[derive(Debug, Clone)]
pub struct SystemError(i32);

impl Error for SystemError {}

impl fmt::Display for SystemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let str = unsafe {
            // Safety: this string will stay alive on this thread until the next call to `strerror`.
            CStr::from_ptr(libc::strerror(self.0))
        };
        write!(f, "system error {:?}: {str:?}", self.0)
    }
}

impl SystemError {
    fn from_errno() -> Self {
        Self(unsafe { *libc::__error() })
    }
}

pub fn page_size_u32() -> u32 {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u32 }
}

pub fn reserve(alloc_size: usize) -> Result<NonNull<()>, SystemError> {
    assert_eq!(alloc_size % page_size(), 0);

    let base_addr = unsafe {
        // According to https://web.archive.org/web/20230517221903/https://www.kernel.org/doc/html/v4.19/vm/overcommit-accounting.html...
        //
        // ```
        // The overcommit is based on the following rules:
        //
        // For an anonymous or /dev/zero map:
        // PRIVATE READ-only - 0 cost (but of little use)
        // ```
        libc::mmap(
            null_mut(),
            alloc_size,
            libc::PROT_READ,
            libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
            -1,
            0,
        )
    };

    if base_addr != libc::MAP_FAILED {
        Ok(NonNull::new(base_addr).unwrap().cast())
    } else {
        Err(SystemError::from_errno())
    }
}

pub unsafe fn unreserve(addr: NonNull<()>, len: usize) {
    assert_eq!(
        libc::munmap(addr.as_ptr().cast(), len),
        0,
        "Failed to unreserve section: {}",
        SystemError::from_errno()
    );
}

pub unsafe fn commit(addr: NonNull<()>, size: usize) -> Result<(), SystemError> {
    let addr = addr.as_ptr().cast();
    assert_eq!(addr as usize % page_size(), 0);
    assert_eq!(size % page_size(), 0);

    let mapped_addr = libc::mmap(
        addr,
        size,
        libc::PROT_READ | libc::PROT_WRITE,
        // N.B. `MAP_FIXED` is allowed to discard underlying mappings.
        //
        // According to `mmap(2)` (https://web.archive.org/web/20230512013353/https://man7.org/linux/man-pages/man2/mmap.2.html):
        // If the memory region specified by addr and length overlaps pages of any
        // existing mapping(s), then the overlapped part of the existing mapping(s)
        // will be discarded.  If the specified address cannot be used, mmap()
        // will fail.
        //
        libc::MAP_ANONYMOUS | libc::MAP_PRIVATE | libc::MAP_FIXED,
        -1,
        0,
    );

    if mapped_addr != libc::MAP_FAILED {
        assert_eq!(addr, mapped_addr);
        Ok(())
    } else {
        Err(SystemError::from_errno())
    }
}

pub unsafe fn uncommit(addr: NonNull<()>, size: usize) {
    let addr = addr.as_ptr().cast();
    assert_eq!(addr as usize % page_size(), 0);
    assert_eq!(size % page_size(), 0);

    let mapped_addr = libc::mmap(
        addr,
        size,
        libc::PROT_READ,
        // N.B. `MAP_FIXED` is allowed to discard underlying mappings.
        libc::MAP_ANONYMOUS | libc::MAP_PRIVATE | libc::MAP_FIXED,
        -1,
        0,
    );

    assert_eq!(addr, mapped_addr);
}
