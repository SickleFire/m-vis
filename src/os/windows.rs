//! # Windows OS Bindings
//!
//! Windows-specific implementations for memory region walking and heap block enumeration.
//! All functions in this module use Win32 APIs and are only compiled on Windows.
//!
//! ## APIs Used
//! - `VirtualQueryEx` — walks the virtual address space of a target process
//! - `GetModuleFileNameExW` — resolves image region base addresses to DLL/EXE paths
//! - `ReadProcessMemory` — reads heap segment data directly for fast block parsing
//! - `Toolhelp32` — enumerates heap base addresses
use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, MEM_RESERVE, MEMORY_BASIC_INFORMATION,
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_GUARD, PAGE_READONLY, PAGE_READWRITE, VirtualQueryEx,
};
use windows::Win32::System::ProcessStatus::GetModuleFileNameExW;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

use crate::types::{HeapBlock, Region, RegionKind, RegionProtect, RegionState};

/// Walks the virtual address space of a process and returns all memory regions.
///
/// Uses `VirtualQueryEx` to enumerate every region in the target process's
/// address space, converting each `MEMORY_BASIC_INFORMATION` entry into a
/// platform-agnostic `Region`.
///
/// For image regions (loaded DLLs and EXEs), attempts to resolve the module
/// path using `GetModuleFileNameExW`. Other region types have an empty name.
///
/// # Arguments
/// * `pid` — target process ID
///
/// # Returns
/// A `Vec<Region>` covering the entire address space from 0 to the top.
/// Free regions are included so the caller can visualize gaps.
///
/// # Panics
/// Panics if `OpenProcess` fails — the process may not exist or access
/// may be denied. Use a process you have `PROCESS_QUERY_INFORMATION` rights to.
pub fn walk_regions(pid: u32) -> Vec<Region> {
    let handle = unsafe {
        OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            .expect("failed to load process")
    };
    let mut regions = Vec::new();
    let mut addr: usize = 0;

    loop {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        let written = unsafe {
            VirtualQueryEx(
                handle,
                Some(addr as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if written == 0 {
            break;
        }

        let region = Region {
            base: mbi.BaseAddress as usize,
            size: mbi.RegionSize,
            state: match mbi.State {
                MEM_COMMIT => RegionState::Committed,
                MEM_RESERVE => RegionState::Reserved,
                _ => RegionState::Free,
            },
            kind: match mbi.Type {
                MEM_IMAGE => RegionKind::Image,
                MEM_MAPPED => RegionKind::Mapped,
                MEM_PRIVATE => RegionKind::Private,
                _ => RegionKind::Unknown,
            },
            protect: if mbi.Protect.contains(PAGE_GUARD) {
                RegionProtect::Guard
            } else if mbi.Protect.contains(PAGE_EXECUTE_READ) || mbi.Protect.contains(PAGE_EXECUTE)
            {
                RegionProtect::Execute
            } else if mbi.Protect.contains(PAGE_READWRITE) {
                RegionProtect::ReadWrite
            } else if mbi.Protect.contains(PAGE_READONLY) {
                RegionProtect::Readonly
            } else {
                RegionProtect::Other
            },
            name: if mbi.Type == MEM_IMAGE {
                let hmodule = HMODULE(mbi.AllocationBase as *mut _);
                let mut buf = vec![0u16; 260]; // MAX_PATH
                let len = unsafe { GetModuleFileNameExW(Some(handle), Some(hmodule), &mut buf) };
                if len > 0 {
                    String::from_utf16_lossy(&buf[..len as usize])
                } else {
                    String::new()
                }
            } else {
                String::new()
            },
        };
        regions.push(region);
        addr = addr.saturating_add(mbi.RegionSize);
        if addr == 0 {
            break;
        }
    }
    regions
}
/// Walks all heap blocks in a process using `ReadProcessMemory` for performance.
///
/// This implementation uses two phases:
/// 1. **Toolhelp32 heap list** — enumerate heap base addresses only.
/// 2. **`ReadProcessMemory`** — read entire heap segments at once.
///
/// # Arguments
/// * `pid` — target process ID
///
/// # Returns
/// A `Vec<HeapBlock>` with address, size, free status, and page protection
/// for each parsed heap block.
pub fn walk_heap(pid: u32) -> Vec<HeapBlock> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, HEAPLIST32, Heap32ListFirst, Heap32ListNext, TH32CS_SNAPHEAPLIST,
    };
    use windows::Win32::System::Memory::{
        MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_NOACCESS, VirtualQueryEx,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    let _t = std::time::Instant::now();
    let mut blocks = Vec::with_capacity(50_000);

    unsafe {
        // open process for reading
        let proc_handle = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
        {
            Ok(h) => h,
            Err(_) => return blocks,
        };

        // phase 1 — collect heap base addresses via Toolhelp32
        // this is fast because we only enumerate heaps, not blocks
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST, pid) {
            Ok(h) => h,
            Err(_) => {
                CloseHandle(proc_handle).ok();
                return blocks;
            }
        };

        let mut heap_bases: Vec<usize> = Vec::new();
        let mut hl = HEAPLIST32::default();
        hl.dwSize = std::mem::size_of::<HEAPLIST32>() as usize;

        if Heap32ListFirst(snapshot, &mut hl).is_ok() {
            loop {
                heap_bases.push(hl.th32HeapID);
                if Heap32ListNext(snapshot, &mut hl).is_err() {
                    break;
                }
            }
        }

        // phase 2 — for each heap base, walk committed regions and parse headers
        for heap_base in heap_bases {
            let mut addr = heap_base;

            loop {
                // query the region at this address
                let mut mbi = MEMORY_BASIC_INFORMATION::default();
                let written = VirtualQueryEx(
                    proc_handle,
                    Some(addr as *const _),
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                );
                if written == 0 {
                    break;
                }

                // only read committed, accessible memory
                if mbi.State == MEM_COMMIT
                    && mbi.Protect.0 != 0
                    && !mbi.Protect.contains(PAGE_NOACCESS)
                    && mbi.RegionSize > 0
                {
                    let mut buf = vec![0u8; mbi.RegionSize];
                    let mut bytes_read = 0usize;
                    let ok = ReadProcessMemory(
                        proc_handle,
                        mbi.BaseAddress,
                        buf.as_mut_ptr() as *mut _,
                        mbi.RegionSize,
                        Some(&mut bytes_read),
                    );

                    if ok.is_ok() && bytes_read >= 8 {
                        let mut offset = 0usize;
                        while offset + 8 <= bytes_read {
                            let size_units =
                                u16::from_le_bytes([buf[offset], buf[offset + 1]]) as usize;

                            if size_units == 0 {
                                break;
                            }

                            let block_size = size_units * 8;
                            if offset + block_size > bytes_read {
                                break;
                            }

                            let flags = buf[offset + 5];
                            let is_busy = (flags & 0x01) != 0;

                            // inherit page protection from the containing region
                            let protect: RegionProtect;
                            if mbi.Protect == PAGE_READONLY {
                                protect = RegionProtect::Readonly;
                            } else if mbi.Protect == PAGE_READWRITE {
                                protect = RegionProtect::ReadWrite;
                            } else if mbi.Protect == PAGE_EXECUTE {
                                protect = RegionProtect::Execute;
                            } else if mbi.Protect == PAGE_EXECUTE_READ {
                                protect = RegionProtect::Execute;
                            } else if mbi.Protect == PAGE_GUARD {
                                protect = RegionProtect::Guard;
                            } else {
                                protect = RegionProtect::Other;
                            }
                            blocks.push(HeapBlock {
                                address: mbi.BaseAddress as usize + offset,
                                size: block_size,
                                is_free: !is_busy,
                                vm_protect: protect,
                            });

                            offset += block_size;
                        }
                    }
                }

                // advance to next region
                let next = addr.saturating_add(mbi.RegionSize);
                if next <= addr {
                    break;
                }
                addr = next;

                // stop when we've moved far from the heap base
                // heap segments are typically contiguous
                if addr > heap_base + 512 * 1024 * 1024 {
                    break;
                }
            }
        }

        CloseHandle(proc_handle).ok();
    }
    blocks
}
