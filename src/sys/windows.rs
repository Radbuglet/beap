//! `win32` quick reference:
//!
//! - https://docs.rs/windows-sys/latest/windows_sys/index.html
//! - https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/
//! - https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc2
//! - https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-createfilemappingw
//! - https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile3
//! - https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-unmapviewoffile2
//! - https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfree
//!

use std::{
    error::Error,
    ffi::CStr,
    fmt,
    mem::MaybeUninit,
    ptr::{null, null_mut, NonNull},
    sync::atomic::AtomicU32,
    sync::atomic::Ordering,
};

use lazy_static::lazy_static;
use windows_sys::{
    core::PSTR,
    Win32::{
        Foundation::{GetLastError, HANDLE, INVALID_HANDLE_VALUE},
        System::{
            Diagnostics::Debug::{
                FormatMessageA, FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_FROM_SYSTEM,
                FORMAT_MESSAGE_IGNORE_INSERTS,
            },
            Memory::{
                CreateFileMappingW, LocalFree, MapViewOfFile3, UnmapViewOfFile2, VirtualAlloc2,
                VirtualFree, MEM_COMMIT, MEM_PRESERVE_PLACEHOLDER, MEM_RELEASE,
                MEM_REPLACE_PLACEHOLDER, MEM_RESERVE, MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS,
                PAGE_READONLY, PAGE_READWRITE,
            },
            SystemInformation::{GetSystemInfo, SYSTEM_INFO},
        },
    },
};

use crate::page_size;

const NULL_HANDLE: HANDLE = 0;

#[derive(Clone)]
pub struct SystemError(u32);

impl Error for SystemError {}

impl fmt::Debug for SystemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SystemError")
            .field(&format!("{}", self))
            .finish()
    }
}

impl fmt::Display for SystemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unsafe {
            // Acquire the error message from the system
            let mut out_str = MaybeUninit::<PSTR>::uninit();
            FormatMessageA(
                /* flags */
                FORMAT_MESSAGE_ALLOCATE_BUFFER
                    | FORMAT_MESSAGE_FROM_SYSTEM
                    | FORMAT_MESSAGE_IGNORE_INSERTS,
                /* source */ null(),
                /* message id */ self.0,
                /* language ID (language neutral -> ... -> locale -> ... -> US English) */ 0,
                /* str pointer out */
                // N.B. Usually, this is an `LPTSTR`. However, when `FORMAT_MESSAGE_ALLOCATE_BUFFER`
                // is specified, this actually takes on the type `*mut LPTSTR`. We can't express
                // this in the type system so weird cast it is!
                out_str.as_mut_ptr().cast(),
                /* min buffer size (given FORMAT_MESSAGE_ALLOCATE_BUFFER) */ 0,
                /* formatting arguments */ null(),
            );

            let out_str = out_str.assume_init();

            // Print it out
            write!(
                f,
                "system error {}: {}",
                self.0,
                CStr::from_ptr(out_str.cast()).to_string_lossy()
            )?;

            // Deallocate the temporary buffer
            LocalFree(out_str as isize);
        }
        Ok(())
    }
}

impl SystemError {
    fn from_errno() -> Self {
        Self(unsafe {
            // Safety: `GetLastError`'s internal errno is stored using TLS.
            GetLastError()
        })
    }

    fn raise(&self) -> ! {
        panic!("{}", self);
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

        // N.B. `dwPageSize` is, indeed, the right choice here.
        //
        // - `dwAllocationGranularity` is the granularity at which regions of memory are reserved.
        // - `dwPageSize` is the granularity at which we can change the pages' protections and their
        //   mappings.
        //
        // We know that `dwAllocationGranularity >= dwPageSize` so it doesn't really matter how much
        // our reservations are aligned, just so long as we can begin subdividing them into
        // committable pages.
        size = sys_info.dwPageSize as u32;
        PAGE_SIZE.store(size, Ordering::Relaxed);
    }
    size
}

lazy_static! {
    // This is the mapping used by all reserved-but-not-committed pages. Because this mapping is
    // shared amongst all of them, we only have to pay the commit charge overhead once.
    static ref NULL_MAP: HANDLE = unsafe {
        CreateFileMappingW(
            /* file */ INVALID_HANDLE_VALUE,
            /* attributes */ null(),
            /* protection */ PAGE_READONLY,
            /* size high */ 0,
            /* size low */ page_size_u32(),
            /* unique name*/ null(),
        )
    };
}

// TODO: Implement cleanup on failure.

// TODO: Code-review because win32 is just super confusing.

pub fn reserve(alloc_size: usize) -> Result<NonNull<()>, SystemError> {
    let page_size = page_size();
    let page_count = alloc_size / page_size;

    // Validate sizes.
    assert_eq!(alloc_size % page_size, 0);
    assert!(
        alloc_size < isize::MAX as usize,
        "Reservation overflows isize::MAX",
    );

    // Reserve a contiguous block of pages. This allocation is currently one big placeholder which
    // cannot be written to or read from.
    let Some(base_addr) = NonNull::new(unsafe {
		VirtualAlloc2(
			/* process */ 
			// N.B. For `VirtualAlloc2`, a `NULL` process handle—not `INVALID_HANDLE_VALUE`—corresponds
			// to allocating memory for the calling process.
			NULL_HANDLE,

			/* base address */ null(),
			/* size */ alloc_size,

			// N.B. This flag combination, although a bit weird, is the only officially valid flag
			// combination producing a usable placeholder page.
			/* flags */ MEM_RESERVE | MEM_RESERVE_PLACEHOLDER,
			/* protection */ PAGE_NOACCESS,

			/* ExtendedParameters + Count */ null_mut(), 0
		)
	}) else {
        return Err(SystemError::from_errno());
    };

    // Map each of the pages to the shared null map. Because we're mapping views rather than creating
    // views or committing memory, we only pay for one page worth of commit charge for all our
    // reservations.
    let addr = base_addr.cast::<u8>();
    let null_map = *NULL_MAP;

    for i in 0..page_count {
        let addr = unsafe { addr.as_ptr().add(i * page_size) };

        // Isolate a placeholder for the page if there isn't already a placeholder of that size at
		// that location.
        if i != page_count - 1 {
            if unsafe {
                VirtualFree(
                    /* base address */ addr.cast(),

					// N.B. The flag combination `MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER` is blessed
					// as being the official way to split a placeholder into two placeholders.
					//
					// The following documentation on MSDN may make you worry that this call is invalid:
					//
					// > If you specify this value [`MEM_RELEASE`], *dwSize* must be 0 (zero), and
					// > *lpAddress* must point to the base address returned by the *VirtualAlloc*
					// > function when the region is reserved. The function fails if either of these
					// > conditions is not met.
					//
					// This documentation, however, is misleading. When they say "specify this value,"
					// they mean "you passed `MEM_RELEASE` verbatim," not "you toggled this flag on."
					//
					// Anyways, win32 is kinda scuffed.
                    /* size */ page_size,
                    /* flags */ MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER,
                )
            } == 0
            {
                return Err(SystemError::from_errno());
            }
        }

        // ...and map it!
        let mapped_addr = unsafe {
			// N.B. The page size is always greater than 64 bytes, as far as I can tell, so the whole
			// "64k-aligned" stuff should not matter.
            MapViewOfFile3(
                /* map */ null_map,
                /* process */ INVALID_HANDLE_VALUE,
                /* base address */ addr.cast(),
                /* size high */ 0,
                /* size low */ page_size,
				/* flags */ MEM_REPLACE_PLACEHOLDER,
                /* protection */ PAGE_READONLY,
                /* extra params */ null_mut(), 0,
            )
        };

        if mapped_addr == 0 {
            return Err(SystemError::from_errno());
        }
    }

    Ok(addr.cast())
}

pub unsafe fn unreserve(addr: NonNull<()>, _len: usize) {
    assert_eq!(addr.as_ptr() as usize % page_size(), 0);

    // This call frees mapped and committed memory indiscriminately, regardless of the whether they
    // belong to the same placeholder.
    let error = VirtualFree(addr.as_ptr().cast(), 0, MEM_RELEASE);
    assert_eq!(error, 0, "{}", SystemError::from_errno());
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
                /* process*/ INVALID_HANDLE_VALUE,
                /* base address */ addr as isize,
                /* flags */ MEM_PRESERVE_PLACEHOLDER,
            )
        } != 1
        {
            return Err(SystemError::from_errno());
        }

        // ...and commit the placeholder's memory.
        if unsafe {
            VirtualAlloc2(
                /* process */ INVALID_HANDLE_VALUE,
                /* base address */ addr.cast(),
                /* size */ page_size,
                /* flags */ MEM_RESERVE | MEM_COMMIT | MEM_REPLACE_PLACEHOLDER,
                /* protection */ PAGE_READWRITE,
                /* ExtendedParameters + Count */ null_mut(), 0,
            )
        }
        .is_null()
        {
            return Err(SystemError::from_errno());
        }
    }

    Ok(())
}

pub unsafe fn uncommit(addr: NonNull<()>, size: usize) {
    let addr = addr.as_ptr().cast::<u8>();
    let page_size = page_size();
    let page_count = size / page_size;
    let null_map = *NULL_MAP;

    // Validate sizes
    assert!(size < isize::MAX as usize);
    assert_eq!(addr as usize % page_size, 0);
    assert_eq!(size % page_size, 0);

    // For every placeholder in the range...
    for i in 0..page_count {
        let addr = unsafe { addr.add(i * page_size) };

        // Decommit its memory...
        if unsafe {
            VirtualFree(
                /* base address */ addr.cast(),
                /* size */ 0,
                /* flags */ MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER,
            )
        } != 0
        {
            SystemError::from_errno().raise();
        }

        // ...and map the null map in its place.
        if unsafe {
            MapViewOfFile3(
                /* map */ null_map,
                /* process */ INVALID_HANDLE_VALUE,
                /* base address */ addr.cast(),
                /* size high */ 0,
                /* size low */ page_size,
                /* flags */ MEM_REPLACE_PLACEHOLDER,
                /* protection */ PAGE_READONLY,
                /* extra params */ null_mut(), 0,
            )
        } == 0
        {
            SystemError::from_errno().raise();
        }
    }
}
