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

use std::{
    error::Error,
    fmt,
    mem::MaybeUninit,
    ptr::{null, null_mut, NonNull},
    sync::atomic::{AtomicU32, Ordering},
};

use lazy_static::lazy_static;
use windows_sys::Win32::{
    Foundation::{GetLastError, HANDLE, INVALID_HANDLE_VALUE},
    System::{
        Memory::{
            CreateFileMappingW, MapViewOfFile3, VirtualAlloc2, VirtualFree,
            MEM_PRESERVE_PLACEHOLDER, MEM_RELEASE, MEM_REPLACE_PLACEHOLDER, MEM_RESERVE,
            MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS, PAGE_READONLY,
        },
        SystemInformation::{GetSystemInfo, SYSTEM_INFO},
    },
};

// https://stackoverflow.com/questions/39984710/virtual-memory-ring-buffer-on-windows
// https://docs.rs/windows-sys/latest/windows_sys/index.html
// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/
// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc2
// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-createfilemappingw
// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile3
// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfree

#[derive(Debug, Clone)]
pub struct SystemError(u32);

impl Error for SystemError {}

impl fmt::Display for SystemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // TODO: Print a string
        write!(f, "System error {:?}", self.0)
    }
}

impl SystemError {
    fn from_errno() -> Self {
        Self(unsafe {
            // Safety: `GetLastError`'s internal errno is stored using TLS.
            GetLastError()
        })
    }
}

pub fn page_size() -> u32 {
    static PAGE_SIZE: AtomicU32 = AtomicU32::new(0);

    let mut size = PAGE_SIZE.load(Ordering::Relaxed);
    if size == 0 {
        let sys_info = unsafe {
            let mut sys_info = MaybeUninit::<SYSTEM_INFO>::uninit();
            GetSystemInfo(sys_info.as_mut_ptr());
            sys_info.assume_init()
        };

        // N.B. according to MaulingMonkey:
        //
        // • Starting page address would be rounded down to an address that's a multiple of
        //   dwAllocationGranularity
        // • Ending page address or page count would be rounded up to an address that's a multiple
        //   of dwPageSize
        //
        // Since we're using `page_size` to determine the granularity of our reservation lengths,
        // commits, and uncommits, this is the number we are looking for.
        size = sys_info.dwPageSize as u32;
        PAGE_SIZE.store(size, Ordering::Relaxed);
    }
    size
}

lazy_static! {
    static ref NULL_MAP: HANDLE = unsafe {
        CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            null(),
            PAGE_READONLY,
            0,
            page_size(),
            null(),
        )
    };
}

pub fn reserve(page_count: usize) -> Result<NonNull<()>, SystemError> {
    let page_size = page_size() as usize;
    let alloc_size = page_size.saturating_mul(page_count);

    // Validate the `page_count`
    assert!(
        alloc_size < isize::MAX as usize,
        "Reservation overflows isize::MAX",
    );

    // Reserve a contiguous block of pages.
    let Some(base_addr) = NonNull::new(unsafe {
		VirtualAlloc2(
			/* Process */ 0,
			null(),
			alloc_size,
			MEM_RESERVE | MEM_RESERVE_PLACEHOLDER,
			PAGE_NOACCESS,
			/* ExtendedParameters + Count */ null_mut(), 0
		)
	}) else {
        return Err(SystemError::from_errno());
    };

    // Map each of the pages to the null map.
    let base_addr = base_addr.cast::<u8>();
    let null_map = *NULL_MAP;

    for i in 0..page_count {
        let page_addr = unsafe { base_addr.as_ptr().add(i * page_size) };

        // Isolate a placeholder for the page if it isn't already of that size.
        if i != page_count - 1 {
            if unsafe {
                VirtualFree(
                    page_addr.cast(),
                    page_size,
                    MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER,
                )
            } == 0
            {
                return Err(SystemError::from_errno());
            }
        }

        // ...and map it!
        //         let mapped_addr = unsafe {
        //             MapViewOfFile3(
        //                 null_map,
        //                 INVALID_HANDLE_VALUE,
        //                 page_addr.cast(),
        //                 0,
        //                 page_size,
        //                 MEM_REPLACE_PLACEHOLDER,
        //                 PAGE_READONLY,
        //                 null_mut(),
        //                 0,
        //             )
        //         };
        //
        //         if mapped_addr == 0 {
        //             return Err(SystemError::from_errno());
        //         }
    }

    Ok(base_addr.cast())
}

pub unsafe fn unreserve(addr: NonNull<()>) {
    // TODO: Error handling
    let _ignored_error = VirtualFree(addr.as_ptr().cast(), 0, MEM_RELEASE);
}

pub unsafe fn commit(addr: NonNull<()>, size: usize) -> Result<(), SystemError> {
    todo!();
}

pub unsafe fn uncommit(addr: NonNull<()>, size: usize) {
    todo!();
}

#[cfg(test)]
mod tests {

    use windows_sys::Win32::System::ProcessStatus::PROCESS_MEMORY_COUNTERS;

    use super::*;

    #[test]
    fn reserve_one_page() {
        reserve(1).unwrap();
    }

    #[test]
    fn reserve_many_pages() {
        reserve(1000).unwrap();
    }

    #[test]
    fn no_commit_on_reserve() {
        let page_count = 10usize.pow(8) / page_size() as usize;

        // Reserve one page before checking `PagefileUsage` to ensure that the null page is created.
        reserve(page_count).unwrap();

        // Reserve a bunch of memory to ensure that it doesn't consume commit charges.
        let mut last_usage = get_stats().PagefileUsage as isize;
        for _ in 0..10 {
            // This will almost certainly exhaust the commit charges available to the application but
            // should not exhaust the virtual address space.
            reserve(page_count).unwrap();

            let curr_usage = get_stats().PagefileUsage as isize;
            let usage_delta = curr_usage - last_usage;
            last_usage = curr_usage;

            assert_eq!(usage_delta, 0);
        }
    }

    fn get_stats() -> PROCESS_MEMORY_COUNTERS {
        use windows_sys::Win32::System::ProcessStatus::GetProcessMemoryInfo;

        unsafe {
            let mut counters = MaybeUninit::<PROCESS_MEMORY_COUNTERS>::uninit();
            GetProcessMemoryInfo(
                0,
                counters.as_mut_ptr(),
                std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
            );
            counters.assume_init()
        }
    }
}
