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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserve_one_page() {
        reserve(page_size()).unwrap();
    }

    #[test]
    fn reserve_many_pages() {
        reserve(page_size() * 1000).unwrap();
    }

    #[test]
    fn reads_zero() {
        let size = 1000 * page_size();
        let page_base = reserve(size).unwrap();
        let page_slice =
            unsafe { std::slice::from_raw_parts(page_base.as_ptr().cast::<u8>(), size) };

        assert!(page_slice.iter().all(|&v| v == 0));
    }

    #[test]
    fn no_commit_on_reserve() {
        let alloc_size = round_up_to_page_size(10usize.pow(8));

        println!("The page size is {}", page_size());

        // Reserve one page before checking `PagefileUsage` to ensure that the null page is created.
        reserve(alloc_size).unwrap();

        // Reserve a bunch of memory to ensure that it doesn't consume commit charges.
        let mut last_usage = peak_memory_usage() as isize;
        for _ in 0..10 {
            // This will almost certainly exhaust the commit charges available to the application but
            // should not exhaust the virtual address space.
            reserve(alloc_size).unwrap();

            let curr_usage = peak_memory_usage() as isize;
            let usage_delta = curr_usage - last_usage;
            last_usage = curr_usage;

            assert_eq!(usage_delta, 0);
        }
    }

    #[test]
    fn can_unreserve() {
        let base = reserve(page_size()).unwrap();
        unsafe { unreserve(base, page_size()) };
    }

    #[test]
    fn commit_and_write() {
        let reserve_size = page_size() * 2;
        // Allocate and check
        let base = reserve(reserve_size).unwrap();
        assert_eq!(unsafe { *base.cast::<u8>().as_ptr() }, 0);

        // Commit and check
        unsafe { commit(base, page_size()) }.unwrap();
        unsafe { *base.cast::<u8>().as_ptr() = 4 };
        assert_eq!(unsafe { *base.cast::<u8>().as_ptr() }, 4);

        // Uncommit and check
        unsafe { uncommit(base, page_size()) };
        assert_eq!(unsafe { *base.cast::<u8>().as_ptr() }, 0);

        // Unreserve
        unsafe { unreserve(base, reserve_size) };
    }

    fn peak_memory_usage() -> usize {
        #[cfg(windows)]
        {
            use windows_sys::Win32::System::ProcessStatus::{
                GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
            };

            let stats = unsafe {
                let mut counters = MaybeUninit::<PROCESS_MEMORY_COUNTERS>::uninit();
                GetProcessMemoryInfo(
                    0,
                    counters.as_mut_ptr(),
                    std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
                );
                counters.assume_init()
            };

            stats.PeakPagefileUsage
        }
        #[cfg(not(windows))]
        {
            0
        }
    }
}
