use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, MEM_RESERVE, MEMORY_BASIC_INFORMATION,
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_GUARD, PAGE_READONLY, PAGE_READWRITE, VirtualQueryEx,
};
use windows::Win32::System::ProcessStatus::GetModuleFileNameExW;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

use crate::types::{HeapBlock, Region, RegionKind, RegionProtect, RegionState};

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

    let t = std::time::Instant::now();
    let mut blocks = Vec::with_capacity(50_000);

    unsafe {
        // open process for reading
        let proc_handle = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
        {
            Ok(h) => h,
            Err(_) => return blocks,
        };

        // get heap base addresses via Toolhelp32 (only 7 calls — fast)
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

        eprintln!("heap count: {}", heap_bases.len());

        // for each heap base, walk all committed regions and parse block headers
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
                    // read the entire region at once — one syscall for thousands of blocks
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

                            blocks.push(HeapBlock {
                                address: mbi.BaseAddress as usize + offset,
                                size: block_size,
                                is_free: !is_busy,
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

    eprintln!(
        "walk_heap: {}ms {} blocks",
        t.elapsed().as_millis(),
        blocks.len()
    );
    blocks
}
