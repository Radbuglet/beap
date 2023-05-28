//! Beap exposes mechanisms for [reserving](reserve) and [unreserving](unreserve) large amounts of
//! memory without contributing to the process' committed memory limit and for dynamically [committing](commit)
//! and [uncommitting](uncommit) those regions without affecting their readability through raw pointers.
//!
//! ## Terminology
//!
//! A given region in memory can be reserved, committed, or backed.
//!
//! - A **reserved** region of memory is a region which is guaranteed not to be allocated by any other
//!   system allocation mechanism. These do not contribute to the operating system's overcommit
//!   protections but may or may not be readable and writable by the process.
//!
//! - A **committed** region of memory may or may not be backed by actual memory. However, the
//!   operating system asserts that, upon first access to the data, the memory will be infallibly
//!   backed by some memory. To provide this guarantee, committed memory counts towards your process'
//!   commit charge count—a virtual representation of how much physical memory the computer could
//!   eventually allocate to a given process.
//!
//! - A **backed** region of memory is backed by RAM or a page file and is thus taking "real" hardware
//!   resources. Although committed regions aren't backed by hardware resources, they are typically
//!   thought as owning some virtual representation of that same resource nonetheless so, for the
//!   purposes of this library, committed and backed memory regions are equivalent.
//!
//! Regions are described at page-level granularity, whose size varies between operating systems. This
//! value can be queried at runtime through [`page_size`].
//!
//! ## Support
//!
//! Beap is not guaranteed to be supported on all platforms so its support should be checked using the
//! [`is_supported`] macro.
//!
//! Currently, the following backends exist:
//!
//! - Unix (`#[cfg(unix)]`), which includes Linux, MacOS, and other POSIX.1-2001-compliant systems.
//!   Although commit charge behavior is not standardized, the behavior relied upon ("`PROT_READ` +
//!   `MAP_ANONYMOUS` + `MAP_PRIVATE` doesn't use any commit charges") is documented in Linux's
//!   [developer documentation](linux-overcommit) and seems to be present on MacOS as well.
//!
//! - Windows (`#[cfg(windows)]`), which includes Windows versions greater than *Windows 10* (client)
//!   and *Windows Server 2016* (server). TODO: Document necessary privileges and slow syscall performance.
//!
//! Additionally, this system is likely only useful for 64 bit systems where the virtual address
//! space is far larger than the actual amount of memory the operating system can give to a process
//! but this recommendation is not enforced by conditional compilation.
//!
//! [linux-overcommit]: https://web.archive.org/web/20230517221903/https://www.kernel.org/doc/html/v4.19/vm/overcommit-accounting.html

// TODO: Add a way to disable windows support in case our process is not running with appropriate
//  privileges or a sufficiently high windows version. We may also want a feature to disable the
//  crate entirely.

// === Platform-specific === //

cfgenius::cond! {
    if cfg(windows) {
        cfgenius::define!(pub is_supported = true());

        #[path = "sys/windows.rs"]
        mod windows;

        pub use windows::*;
    } else if cfg(unix) {
        cfgenius::define!(pub is_supported = true());

        #[cfg(unix)]
        #[path = "sys/unix.rs"]
        mod unix;

        #[cfg(unix)]
        pub use unix::*;
    } else {
        cfgenius::define!(pub is_supported = false());
    }
}

// === Platform Agnostic === //

pub const IS_SUPPORTED: bool = cfgenius::cond_expr!(macro(is_supported));

cfgenius::cond! {
    if macro(is_supported) {
        pub fn round_up_to_page_size(size: usize) -> usize {
            let page_size = page_size();

            (size.saturating_add(page_size - 1) / page_size) * page_size
        }

        pub fn page_size() -> usize {
            page_size_u32() as usize
        }

        #[cfg(test)]
        mod tests;
    }
}
