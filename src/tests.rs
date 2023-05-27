use std::ptr::NonNull;

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
    let size = page_size() * 1000;
    let page_base = reserve(size).unwrap();
    let page_slice = unsafe { std::slice::from_raw_parts(page_base.as_ptr().cast::<u8>(), size) };

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
    println!("The page size is {}", page_size());

    for page_count in [1, 2, 4] {
        let reserve_size = page_size() * page_count;

        for page_offset in 0..page_count {
            // Allocate and check
            let base = reserve(reserve_size).unwrap();
            let page =
                NonNull::new(unsafe { base.as_ptr().add(page_size() * page_offset) }).unwrap();

            assert_eq!(unsafe { *page.cast::<u8>().as_ptr() }, 0);

            for _ in 0..10 {
                // Commit and check
                unsafe { commit(page, page_size()) }.unwrap();
                unsafe { *page.cast::<u8>().as_ptr() = 4 };
                assert_eq!(unsafe { *page.cast::<u8>().as_ptr() }, 4);

                // Uncommit and check
                unsafe { uncommit(page, page_size()) };
                assert_eq!(unsafe { *page.cast::<u8>().as_ptr() }, 0);
            }

            // Unreserve
            unsafe { unreserve(base, reserve_size) };
        }
    }
}

fn peak_memory_usage() -> usize {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::ProcessStatus::{
            GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
        };

        let stats = unsafe {
            let mut counters = std::mem::MaybeUninit::<PROCESS_MEMORY_COUNTERS>::uninit();
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
        // TODO: Add support for Darwin and Linux
        0
    }
}
