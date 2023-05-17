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
            CreateFileMappingW, MapViewOfFile3, UnmapViewOfFile2, VirtualAlloc2, VirtualFree,
            MEM_PRESERVE_PLACEHOLDER, MEM_RELEASE, MEM_REPLACE_PLACEHOLDER, MEM_RESERVE,
            MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE,
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

pub fn page_size_u32() -> u32 {
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

pub fn page_size() -> usize {
    page_size_u32() as usize
}

pub fn round_up_to_page_size(size: usize) -> usize {
    let page_size = page_size();

    (size.saturating_add(page_size - 1) / page_size) * page_size
}

lazy_static! {
    static ref NULL_MAP: HANDLE = unsafe {
        CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            null(),
            PAGE_READONLY,
            0,
            page_size_u32(),
            null(),
        )
    };
}

// TODO: Implement cleanup on failure.

pub fn reserve(alloc_size: usize) -> Result<NonNull<()>, SystemError> {
    let page_size = page_size();
    let page_count = alloc_size / page_size;

    // Validate sizes.
    assert_eq!(alloc_size % page_size, 0);
    assert!(
        alloc_size < isize::MAX as usize,
        "Reservation overflows isize::MAX",
    );

    // Reserve a contiguous block of pages.
    let Some(base_addr) = NonNull::new(unsafe {
		VirtualAlloc2(
			/* process */ INVALID_HANDLE_VALUE,
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
        let mapped_addr = unsafe {
            MapViewOfFile3(
                /* map */ null_map,
                /* process */ INVALID_HANDLE_VALUE,
                /* base address */ page_addr.cast(),
                /* size high */ 0,
                /* size low */ page_size,
                MEM_REPLACE_PLACEHOLDER,
                PAGE_READONLY,
                null_mut(),
                0,
            )
        };

        if mapped_addr == 0 {
            return Err(SystemError::from_errno());
        }
    }

    Ok(base_addr.cast())
}

pub unsafe fn unreserve(addr: NonNull<()>) {
    debug_assert_eq!(addr.as_ptr() as usize % page_size(), 0);

    let error = VirtualFree(addr.as_ptr().cast(), 0, MEM_RELEASE);
    debug_assert_eq!(error, 0);
}

pub unsafe fn commit(addr: NonNull<()>, size: usize) -> Result<(), SystemError> {
    let addr = addr.as_ptr().cast::<u8>();
    let page_size = page_size();
    let page_count = size / page_size;

    // Validate sizes
    assert!(size < isize::MAX as usize);
    assert_eq!(addr as usize % page_size, 0);
    assert_eq!(size % page_size, 0);

    // For every placeholder in the range...
    for i in 0..page_count {
        let addr = unsafe { addr.add(i * page_size) };

        // Remove its mapping...
        if unsafe {
            UnmapViewOfFile2(
                INVALID_HANDLE_VALUE,
                addr as isize,
                MEM_PRESERVE_PLACEHOLDER,
            )
        } != 1
        {
            return Err(SystemError::from_errno());
        }

        // ...and commit the placeholder's memory.
        if unsafe {
            VirtualAlloc2(
                0,
                addr.cast(),
                page_size,
                MEM_REPLACE_PLACEHOLDER,
                PAGE_READWRITE,
                null_mut(),
                0,
            )
        }
        .is_null()
        {
            return Err(SystemError::from_errno());
        }
    }

    Ok(())
}

pub unsafe fn uncommit(_addr: NonNull<()>, _size: usize) {
    todo!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::System::ProcessStatus::{
        GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };

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
        let mut last_usage = get_stats().PeakPagefileUsage as isize;
        for _ in 0..10 {
            // This will almost certainly exhaust the commit charges available to the application but
            // should not exhaust the virtual address space.
            reserve(alloc_size).unwrap();

            let curr_usage = get_stats().PeakPagefileUsage as isize;
            let usage_delta = curr_usage - last_usage;
            last_usage = curr_usage;

            assert_eq!(usage_delta, 0);
        }
    }

    #[test]
    fn can_unreserve() {
        let base = reserve(page_size()).unwrap();
        unsafe { unreserve(base) };
    }

    #[test]
    fn commit_and_write() {
        // Allocate and check
        let base = reserve(page_size() * 2).unwrap();
        assert_eq!(unsafe { *base.cast::<u8>().as_ptr() }, 0);

        // Commit and check
        unsafe { commit(base, page_size()) }.unwrap();
        unsafe { *base.cast::<u8>().as_ptr() = 4 };
        assert_eq!(unsafe { *base.cast::<u8>().as_ptr() }, 0);

        // Unreserve
        unsafe { unreserve(base) };
    }

    fn get_stats() -> PROCESS_MEMORY_COUNTERS {
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
