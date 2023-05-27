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
//!   protections.
//!
//! - A **committed** region of memory may or may not be backed by actual memory. However, the
//!   operating system asserts that, upon first access to the data, the memory will be infallibly
//!   backed by some memory. To provide this guarantee, committed memory counts towards your process'
//!   commit charge count, which the operating system uses for overcommit protection.
//!
//! - A **backed** region of memory is backed by RAM or a page file and is thus taking "real" hardware
//!   resources. Although committed regions aren't backed by hardware resources, they are typically
//!   thought as owning some virtual representation of that same resource nonetheless so, for the
//!   purposes of this library, committed and backed memory regions are equivalent.
//!
//! Regions are described at page-level granularity, whose size varies between operating systems. This
//! value can be queried at runtime through [`page_size`].

#[cfg(any(windows, unix))]
#[macro_export]
macro_rules! is_supported {
    (
		$(true => { $($true:tt)* })?
		$(false => { $($false:tt)* })?
	) => {
		$($($true)*)?
	};
}

#[cfg(not(any(windows, unix)))]
#[macro_export]
macro_rules! is_supported {
    (
		$(true => { $($true:tt)* })?
		$(false => { $($false:tt)* })?
	) => {
		$($($false)*)?
	};
}

is_supported! {
    true => {
        // === Platform Specific === //

        #[cfg(windows)]
        #[path = "sys/windows.rs"]
        mod windows;

        #[cfg(windows)]
        pub use windows::*;

        #[cfg(unix)]
        #[path = "sys/unix.rs"]
        mod unix;

        #[cfg(unix)]
        pub use unix::*;

        // === Platform Agnostic === //

        pub fn round_up_to_page_size(size: usize) -> usize {
            let page_size = page_size();

            (size.saturating_add(page_size - 1) / page_size) * page_size
        }

        pub fn page_size() -> usize {
            page_size_u32() as usize
        }

        // === Tests === //

        #[cfg(test)]
        mod tests;
    }
}
