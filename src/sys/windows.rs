// win32 quick reference:
// https://stackoverflow.com/questions/39984710/virtual-memory-ring-buffer-on-windows
// https://docs.rs/windows-sys/latest/windows_sys/index.html
// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/
// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc2
// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-createfilemappingw
// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile3
// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfree

use std::{
    error::Error,
    fmt,
    mem::MaybeUninit,
    ptr::{null, null_mut, NonNull},
    sync::atomic::AtomicU32,
    sync::atomic::Ordering,
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

use crate::page_size;

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

pub unsafe fn unreserve(addr: NonNull<()>, _len: usize) {
    assert_eq!(addr.as_ptr() as usize % page_size(), 0);

    let error = VirtualFree(addr.as_ptr().cast(), 0, MEM_RELEASE);
    assert_eq!(error, 0);
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
