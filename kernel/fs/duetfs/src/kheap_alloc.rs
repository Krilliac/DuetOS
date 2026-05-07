// Global allocator — bridges Rust's `alloc::*` types to the kernel
// heap (mm::KMalloc / mm::KFree) via two C symbols the C++ side
// resolves at link time. No allocation happens before the kernel
// heap is up; callers stage every Vec / Box behind a `Fs` open or
// `crypto` API call, both of which run after kernel_main has
// brought up `KernelHeapInit`.
//
// Alignment: the kernel heap guarantees a 16-byte payload
// alignment. For Layouts requesting larger alignment, we over-
// allocate by `align - 1`, store the original chunk pointer in the
// 8 bytes preceding the aligned payload, and recover it at
// dealloc. 2 KiB upper bound on alignment is enforced — anything
// larger is a bug in the caller.

use core::alloc::{GlobalAlloc, Layout};

extern "C"
{
    fn duetos_rust_alloc(bytes: usize) -> *mut u8;
    fn duetos_rust_free(ptr: *mut u8);
}

const KERNEL_HEAP_ALIGN: usize = 16;
const MAX_OVERALIGN: usize = 2048;

struct KernelHeapAllocator;

unsafe impl GlobalAlloc for KernelHeapAllocator
{
    unsafe fn alloc(&self, layout: Layout) -> *mut u8
    {
        let size = layout.size();
        let align = layout.align();
        if size == 0
        {
            return core::ptr::null_mut();
        }
        if align <= KERNEL_HEAP_ALIGN
        {
            return unsafe { duetos_rust_alloc(size) };
        }
        if align > MAX_OVERALIGN
        {
            return core::ptr::null_mut();
        }
        // Over-allocate so we can find an `align`-aligned address
        // inside the chunk and stash the original pointer before it.
        let total = size + align + core::mem::size_of::<*mut u8>();
        let raw = unsafe { duetos_rust_alloc(total) };
        if raw.is_null()
        {
            return core::ptr::null_mut();
        }
        let raw_addr = raw as usize;
        let payload_addr = (raw_addr + core::mem::size_of::<*mut u8>() + (align - 1)) & !(align - 1);
        let payload = payload_addr as *mut u8;
        unsafe {
            // Stash the original chunk pointer in the 8 bytes preceding
            // the aligned payload so dealloc can recover it.
            let stash = payload.sub(core::mem::size_of::<*mut u8>()) as *mut *mut u8;
            *stash = raw;
        }
        payload
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout)
    {
        if ptr.is_null()
        {
            return;
        }
        if layout.align() <= KERNEL_HEAP_ALIGN
        {
            unsafe { duetos_rust_free(ptr) };
            return;
        }
        // Recover the original chunk pointer from the stash.
        let stash = unsafe { ptr.sub(core::mem::size_of::<*mut u8>()) as *const *mut u8 };
        let raw = unsafe { *stash };
        unsafe { duetos_rust_free(raw) };
    }
}

#[global_allocator]
static GLOBAL: KernelHeapAllocator = KernelHeapAllocator;
