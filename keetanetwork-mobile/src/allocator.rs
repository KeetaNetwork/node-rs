use std::alloc::{GlobalAlloc, Layout, System};
use std::mem::MaybeUninit;
use zeroize::Zeroize;

/// Clears each allocation on release. This covers copies of a secret that dependencies and the FFI buffers make.
pub struct ZeroizingAllocator;

// SAFETY: `System` satisfies the allocator contract, and `dealloc` writes only inside the allocation it releases.
unsafe impl GlobalAlloc for ZeroizingAllocator {
	unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
		unsafe { System.alloc(layout) }
	}

	unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
		unsafe {
			std::slice::from_raw_parts_mut(pointer.cast::<MaybeUninit<u8>>(), layout.size()).zeroize();
			System.dealloc(pointer, layout);
		}
	}
}
