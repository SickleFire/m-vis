#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "windows")]
pub use windows::find_blocks_with_pointers;

#[cfg(target_os = "windows")]
pub use windows::walk_heap_granular;

#[cfg(target_os = "windows")]
pub use windows::WindowsMemory as PlatformMemory;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::LinuxMemory as PlatformMemory;

//pub use linux::LinuxMemory as PlatformMemory;

use crate::types::{HeapBlock, ModuleInfo, Region};

/// Returns the platform-specific [`MemoryProvider`] instance.
pub fn provider() -> PlatformMemory {
    PlatformMemory
}

/// Abstraction over OS-specific memory inspection APIs.
pub trait MemoryProvider {
    /// Returns all virtual memory regions mapped into the process with the given `pid`.
    fn walk_regions(&self, pid: u32) -> Vec<Region>;
    /// Returns all heap blocks (both used and free) for the process with the given `pid`.
    fn walk_heap(&self, pid: u32) -> Vec<HeapBlock>;
    /// Returns loaded modules for the process with the given `pid`.
    ///
    /// Pass `"-t"` as `flag` to restrict the output to tampered or injected modules only.
    fn list_modules(&self, pid: u32, flag: String) -> Vec<ModuleInfo>;
}
