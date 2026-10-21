//! # Windows OS Bindings
//!
//! Windows-specific implementations for memory region walking and heap block enumeration.
//! All functions in this module use Win32 APIs and are only compiled on Windows.
//!
//! ## APIs Used
//! - `VirtualQueryEx` — walks the virtual address space of a target process
//! - `GetModuleFileNameExW` — resolves image region base addresses to DLL/EXE paths
//! - `ReadProcessMemory` — reads target memory for pointer scanning and dumps
//! - `Toolhelp32` — enumerates heap entries
use std::collections::{HashMap, HashSet};
use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, MEM_RESERVE, MEMORY_BASIC_INFORMATION,
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_GUARD, PAGE_READONLY, PAGE_READWRITE, VirtualQueryEx,
};
use windows::Win32::System::ProcessStatus::GetModuleFileNameExW;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

use crate::os::MemoryProvider;
use crate::types::{
    HeapBlock, ModuleInfo, ModuleStatus, PointerEdge, Region, RegionKind, RegionProtect,
    RegionState,
};

pub struct WindowsMemory;

impl MemoryProvider for WindowsMemory {
    fn walk_regions(&self, pid: u32) -> Result<Vec<Region>, String> {
        walk_regions(pid)
    }

    fn walk_heap(&self, pid: u32) -> Result<Vec<HeapBlock>, String> {
        Ok(walk_heap(pid))
    }

    fn list_modules(&self, pid: u32, flag: String) -> Result<Vec<ModuleInfo>, String> {
        Ok(list_modules(pid, flag))
    }

    fn read_process_memory(
        &self,
        pid: u32,
        address: usize,
        size: usize,
    ) -> Result<Vec<u8>, String> {
        Ok(read_process_memory_bytes(pid, address, size)?)
    }

    fn walk_heap_granular(&self, pid: u32) -> Result<Vec<HeapBlock>, String> {
        Ok(walk_heap_granular(pid))
    }

    fn find_pointer_edges(
        &self,
        pid: u32,
        blocks: &[HeapBlock],
    ) -> Result<HashMap<usize, Vec<PointerEdge>>, String> {
        Ok(find_pointer_edges(pid, blocks))
    }
}

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
pub fn walk_regions(pid: u32) -> Result<Vec<Region>, String> {
    let handle = unsafe {
        OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            .expect("failed to load process")
    };
    let mut regions = Vec::new();
    let mut addr: usize = 0;
    let mut region_count = 0;
    const MAX_REGIONS_PER_PROCESS: usize = 100_000;

    loop {
        region_count += 1;
        if region_count % 10_000 == 0 {
            eprintln!(
                "walk_regions: processed {} regions for pid {}",
                region_count, pid
            );
        }
        if region_count > MAX_REGIONS_PER_PROCESS {
            return Err("Process has too many regions".into());
        }
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
    Ok(regions)
}
/// Enumerates heap entries with Toolhelp32. The reported granularity depends on
/// the Windows heap implementation and may combine multiple small allocations.
pub fn walk_heap(pid: u32) -> Vec<HeapBlock> {
    walk_heap_granular(pid)
}

/// Enumerates heap entries for the process using Toolhelp32 `HEAPENTRY32` records.
///
/// This is the standard Windows heap walk. Some heap implementations still report multiple
/// small allocations as one range.
pub fn walk_heap_granular(pid: u32) -> Vec<HeapBlock> {
    use std::time::{Duration, Instant};
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, HEAPENTRY32, HEAPLIST32, Heap32First, Heap32ListFirst,
        Heap32ListNext, Heap32Next, TH32CS_SNAPHEAPLIST,
    };

    const MAX_BLOCKS_PER_HEAP: usize = 100_000;
    const MAX_TOTAL_BLOCKS: usize = 1_000_000;
    const MAX_WALK_DURATION: Duration = Duration::from_secs(10);

    let start = Instant::now();
    let mut blocks = Vec::new();

    unsafe {
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST, pid) {
            Ok(h) => h,
            Err(error) => {
                eprintln!("walk_heap_granular: snapshot failed for pid {pid}: {error:?}");
                return blocks;
            }
        };

        let mut hl = HEAPLIST32 {
            dwSize: std::mem::size_of::<HEAPLIST32>(),
            ..Default::default()
        };

        if Heap32ListFirst(snapshot, &mut hl).is_err() {
            CloseHandle(snapshot).ok();
            return blocks;
        }

        'heaps: loop {
            let mut blocks_this_heap = 0;
            let mut he = HEAPENTRY32 {
                dwSize: std::mem::size_of::<HEAPENTRY32>(),
                ..Default::default()
            };

            if Heap32First(&mut he, pid, hl.th32HeapID).is_ok() {
                loop {
                    if start.elapsed() > MAX_WALK_DURATION {
                        eprintln!(
                            "walk_heap_granular: exceeded time budget for pid {pid}, aborting walk"
                        );
                        break 'heaps;
                    }
                    if blocks.len() >= MAX_TOTAL_BLOCKS {
                        eprintln!(
                            "walk_heap_granular: exceeded total block cap for pid {pid}, aborting walk"
                        );
                        break 'heaps;
                    }
                    if blocks_this_heap >= MAX_BLOCKS_PER_HEAP {
                        eprintln!(
                            "walk_heap_granular: heap {:#x} exceeded block cap, skipping rest",
                            hl.th32HeapID
                        );
                        break;
                    }

                    let is_free = (he.dwFlags.0 & 0x2) != 0; // LF32_FREE = 0x2

                    blocks.push(HeapBlock {
                        address: he.dwAddress,
                        size: he.dwBlockSize,
                        is_free,
                        vm_protect: RegionProtect::ReadWrite,
                    });
                    blocks_this_heap += 1;

                    if Heap32Next(&mut he).is_err() {
                        break;
                    }
                }
            }

            if Heap32ListNext(snapshot, &mut hl).is_err() {
                break;
            }
        }

        CloseHandle(snapshot).ok();
    }
    blocks
}

/// Reads `size` raw bytes from target process memory at `address`.
pub fn read_process_memory_bytes(pid: u32, address: usize, size: usize) -> Result<Vec<u8>, String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    unsafe {
        let proc_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            .map_err(|e| format!("Failed to open process {pid}: {e:?}"))?;

        let mut buf = vec![0u8; size];
        let mut bytes_read = 0usize;

        let ok = ReadProcessMemory(
            proc_handle,
            address as *const _,
            buf.as_mut_ptr() as *mut _,
            size,
            Some(&mut bytes_read),
        );

        CloseHandle(proc_handle).ok();

        if ok.is_ok() && bytes_read > 0 {
            buf.truncate(bytes_read);
            Ok(buf)
        } else {
            Err(format!(
                "Failed to read memory at 0x{address:x} for PID {pid}"
            ))
        }
    }
}

/// Scans live heap blocks for pointer-like values and resolves each against
/// the full block list (live + free) via binary search.
///
/// Edges into a freed block are marked `target_is_free: true` — a live block
/// still holding a reference to freed memory is a dangling-pointer / UAF signal.
pub fn find_pointer_edges(pid: u32, blocks: &[HeapBlock]) -> HashMap<usize, Vec<PointerEdge>> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

    let mut edges: HashMap<usize, Vec<PointerEdge>> = HashMap::new();

    unsafe {
        let proc_handle = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
        {
            Ok(h) => h,
            Err(_) => return edges,
        };

        // (start, end, is_free) sorted by start — O(log n) containment lookup
        // instead of the old linear scan per pointer word.
        let mut ranges: Vec<(usize, usize, bool)> = blocks
            .iter()
            .map(|b| (b.address, b.address + b.size, b.is_free))
            .collect();
        ranges.sort_by_key(|&(start, _, _)| start);

        let find_containing = |value: usize| -> Option<(usize, bool)> {
            let idx = ranges.partition_point(|&(start, _, _)| start <= value);
            if idx == 0 {
                return None;
            }
            let (start, end, is_free) = ranges[idx - 1];
            (value >= start && value < end).then_some((start, is_free))
        };

        let mut seen_edges = HashSet::new();
        for block in blocks.iter().filter(|b| !b.is_free) {
            const MAX_BLOCK_READ: usize = 64 * 1024;
            let mut buf = vec![0u8; block.size.min(MAX_BLOCK_READ)];
            let mut bytes_read = 0usize;

            let ok = ReadProcessMemory(
                proc_handle,
                block.address as *const _,
                buf.as_mut_ptr() as *mut _,
                buf.len(),
                Some(&mut bytes_read),
            );

            if ok.is_err() || bytes_read < 8 {
                continue;
            }

            append_pointer_edges(
                block,
                &buf[..bytes_read],
                &find_containing,
                &mut seen_edges,
                &mut edges,
            );
        }

        CloseHandle(proc_handle).ok();
    }

    edges
}

fn append_pointer_edges(
    block: &HeapBlock,
    bytes: &[u8],
    find_containing: &impl Fn(usize) -> Option<(usize, bool)>,
    seen_edges: &mut HashSet<(usize, usize, usize, usize)>,
    edges: &mut HashMap<usize, Vec<PointerEdge>>,
) {
    let mut offset = 0;
    while offset + 8 <= bytes.len() {
        let value = usize::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());

        if let Some((target, target_is_free)) = find_containing(value) {
            let source_address = block.address.saturating_add(offset);
            if seen_edges.insert((block.address, target, value, source_address)) {
                edges.entry(block.address).or_default().push(PointerEdge {
                    target,
                    target_is_free,
                    pointer_value: value,
                    source_address,
                    observed_stack: None,
                    stack_trace_error: None,
                });
            }
        }

        offset += 8;
    }
}

/// Coarse tagged/referenced sets for the Allocations table, derived from the
/// same edge graph the Pointer Tree view uses.
fn find_blocks_with_pointers(
    pid: u32,
    blocks: &[HeapBlock],
) -> (
    std::collections::HashSet<usize>,
    std::collections::HashSet<usize>,
) {
    let edges = find_pointer_edges(pid, blocks);
    let tagged: std::collections::HashSet<usize> = edges.keys().copied().collect();
    let referenced: std::collections::HashSet<usize> = edges
        .values()
        .flatten()
        .filter(|e| !e.target_is_free)
        .map(|e| e.target)
        .collect();
    (tagged, referenced)
}

/// Lists all loaded modules in a process and checks their integrity.
///
/// For each image region:
/// 1. Deduplicates by DLL path (multiple regions per DLL)
/// 2. Checks if the file exists on disk — missing = injected
/// 3. Compares the `.text` section in memory vs disk — differs = tampered
///
/// # Arguments
/// * `pid` — target process ID
///
/// # Returns
/// A `Vec<ModuleInfo>` with one entry per loaded DLL/EXE
pub fn list_modules(pid: u32, flag: String) -> Vec<ModuleInfo> {
    use windows::Win32::Foundation::CloseHandle;
    let tampered: bool = flag == "-t";
    let mut modules: HashMap<String, ModuleInfo> = HashMap::new();

    unsafe {
        let proc_handle = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
        {
            Ok(h) => h,
            Err(_) => return vec![],
        };

        // walk regions and collect image regions grouped by path
        let regions = walk_regions(pid).unwrap_or_default();
        for region in regions
            .iter()
            .filter(|r| r.kind == RegionKind::Image && !r.name.is_empty())
        {
            modules.entry(region.name.clone()).or_insert(ModuleInfo {
                base: region.base,
                size: 0,
                name: std::path::Path::new(&region.name)
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
                path: region.name.clone(),
                status: ModuleStatus::Ok,
            });

            // accumulate total size
            if let Some(m) = modules.get_mut(&region.name) {
                m.size += region.size;
                // use lowest base address
                if region.base < m.base {
                    m.base = region.base;
                }
            }
        }

        // check integrity for each module
        for (path, module) in modules.iter_mut() {
            // check if file exists on disk
            if !std::path::Path::new(path).exists() {
                module.status = ModuleStatus::Injected;
                continue;
            }

            // read .text section from disk
            let disk_bytes = match read_text_section_from_disk(path) {
                Some(b) => b,
                None => {
                    module.status = ModuleStatus::Unreadable;
                    continue;
                }
            };

            // read same range from memory
            let mem_bytes =
                match read_text_section_from_memory(proc_handle, module.base, disk_bytes.len()) {
                    Some(b) => b,
                    None => {
                        module.status = ModuleStatus::Unreadable;
                        continue;
                    }
                };

            module.status = check_integrity(&disk_bytes, &mem_bytes);
        }

        CloseHandle(proc_handle).ok();
    }
    let mut result: Vec<ModuleInfo> = vec![];
    if tampered {
        result = modules
            .into_values()
            .filter(|m| m.status != ModuleStatus::Ok)
            .collect();
    } else {
        result = modules.into_values().collect();
    }
    result.sort_by(|a, b| a.base.cmp(&b.base));
    result
}

/// Reads the .text section from a PE file on disk.
fn read_text_section_from_disk(path: &str) -> Option<Vec<u8>> {
    use std::fs;
    use std::io::Read;

    let mut file = fs::File::open(path).ok()?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).ok()?;

    // parse PE header to find .text section
    // DOS header magic: MZ = 0x5A4D
    if buf.len() < 64 {
        return None;
    }
    if buf[0] != 0x4D || buf[1] != 0x5A {
        return None;
    }

    let pe_offset = u32::from_le_bytes(buf[0x3C..0x40].try_into().ok()?) as usize;
    if pe_offset + 4 > buf.len() {
        return None;
    }

    // PE signature: PE\0\0
    if &buf[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return None;
    }

    let num_sections =
        u16::from_le_bytes(buf[pe_offset + 6..pe_offset + 8].try_into().ok()?) as usize;

    let opt_header_size =
        u16::from_le_bytes(buf[pe_offset + 20..pe_offset + 22].try_into().ok()?) as usize;

    let section_start = pe_offset + 24 + opt_header_size;

    for i in 0..num_sections {
        let sec_offset = section_start + i * 40;
        if sec_offset + 40 > buf.len() {
            break;
        }

        let name = &buf[sec_offset..sec_offset + 8];
        if name.starts_with(b".text") {
            let raw_size =
                u32::from_le_bytes(buf[sec_offset + 16..sec_offset + 20].try_into().ok()?) as usize;
            let raw_offset =
                u32::from_le_bytes(buf[sec_offset + 20..sec_offset + 24].try_into().ok()?) as usize;

            if raw_offset + raw_size > buf.len() {
                return None;
            }
            return Some(buf[raw_offset..raw_offset + raw_size].to_vec());
        }
    }

    None
}

/// Reads `size` bytes from a process starting at `base_address`.
fn read_text_section_from_memory(
    proc_handle: windows::Win32::Foundation::HANDLE,
    base: usize,
    size: usize,
) -> Option<Vec<u8>> {
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

    let mut header_buf = vec![0u8; 0x1000];
    let mut bytes_read = 0usize;

    unsafe {
        ReadProcessMemory(
            proc_handle,
            base as *const _,
            header_buf.as_mut_ptr() as *mut _,
            header_buf.len(),
            Some(&mut bytes_read),
        )
        .ok()?;
    }

    if bytes_read < 64 {
        return None;
    }
    if header_buf[0] != 0x4D || header_buf[1] != 0x5A {
        return None;
    }

    let pe_offset = u32::from_le_bytes(header_buf[0x3C..0x40].try_into().ok()?) as usize;
    let num_sections =
        u16::from_le_bytes(header_buf[pe_offset + 6..pe_offset + 8].try_into().ok()?) as usize;
    let opt_header_size =
        u16::from_le_bytes(header_buf[pe_offset + 20..pe_offset + 22].try_into().ok()?) as usize;
    let section_start = pe_offset + 24 + opt_header_size;

    for i in 0..num_sections {
        let sec_offset = section_start + i * 40;
        if sec_offset + 40 > bytes_read {
            break;
        }

        let name = &header_buf[sec_offset..sec_offset + 8];
        if name.starts_with(b".text") {
            let virtual_addr = u32::from_le_bytes(
                header_buf[sec_offset + 12..sec_offset + 16]
                    .try_into()
                    .ok()?,
            ) as usize;
            let virtual_size = u32::from_le_bytes(
                header_buf[sec_offset + 8..sec_offset + 12]
                    .try_into()
                    .ok()?,
            ) as usize;

            let read_size = virtual_size.min(size);
            let mut text_buf = vec![0u8; read_size];
            let mut bytes_read = 0usize;

            unsafe {
                ReadProcessMemory(
                    proc_handle,
                    (base + virtual_addr) as *const _,
                    text_buf.as_mut_ptr() as *mut _,
                    read_size,
                    Some(&mut bytes_read),
                )
                .ok()?;
            }

            return Some(text_buf[..bytes_read].to_vec());
        }
    }

    None
}

fn check_integrity(disk: &[u8], mem: &[u8]) -> ModuleStatus {
    if disk.is_empty() || mem.is_empty() {
        return ModuleStatus::Unreadable;
    }

    let page_size = 0x1000;
    let mut dirty = 0usize;
    let mut _total = 0usize;
    let compare_len = disk.len().min(mem.len());

    let mut offset = 0;
    while offset < compare_len {
        let end = (offset + page_size).min(compare_len);
        _total += 1;
        if disk[offset..end] != mem[offset..end] {
            dirty += 1;
        }
        offset += page_size;
    }

    if dirty > 0 {
        ModuleStatus::Tampered
    } else {
        ModuleStatus::Ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pointer_scan_keeps_intra_block_targets_after_first_page() {
        let mut bytes = vec![0; 0x3000];
        let base = bytes.as_ptr() as usize;
        let source_offset = 0x1800;
        let pointer_value = base + 0x1900;
        bytes[source_offset..source_offset + 8].copy_from_slice(&pointer_value.to_le_bytes());
        let block = HeapBlock {
            address: base,
            size: bytes.len(),
            is_free: false,
            vm_protect: RegionProtect::ReadWrite,
        };
        let edges = find_pointer_edges(std::process::id(), std::slice::from_ref(&block));
        let edge = edges[&base]
            .iter()
            .find(|edge| edge.pointer_value == pointer_value)
            .unwrap();
        assert_eq!(edge.source_address, block.address + source_offset);
        assert_eq!(edge.target, block.address);
        assert!(!edge.target_is_free);
    }

    // Helper to make a vec of given length filled with a value
    fn make_page(value: u8, len: usize) -> Vec<u8> {
        let page = vec![value; len];
        page
    }

    // --- Edge cases: empty inputs ---

    #[test]
    fn test_empty_disk_returns_unreadable() {
        assert_eq!(
            check_integrity(&[], &[0u8; 0x1000]),
            ModuleStatus::Unreadable
        );
    }

    #[test]
    fn test_empty_mem_returns_unreadable() {
        assert_eq!(
            check_integrity(&[0u8; 0x1000], &[]),
            ModuleStatus::Unreadable
        );
    }

    #[test]
    fn test_both_empty_returns_unreadable() {
        assert_eq!(check_integrity(&[], &[]), ModuleStatus::Unreadable);
    }

    // --- Clean: identical content ---

    #[test]
    fn test_identical_single_page_returns_ok() {
        let data = make_page(0xAB, 0x1000);
        assert_eq!(check_integrity(&data, &data), ModuleStatus::Ok);
    }

    #[test]
    fn test_identical_multi_page_returns_ok() {
        let data = make_page(0xFF, 0x4000); // 4 pages
        assert_eq!(check_integrity(&data, &data), ModuleStatus::Ok);
    }

    #[test]
    fn test_identical_sub_page_returns_ok() {
        // Less than one full page — only partial page is compared
        let data = vec![0x01u8; 0x800];
        assert_eq!(check_integrity(&data, &data), ModuleStatus::Ok);
    }

    // --- Tampered: differing content ---

    #[test]
    fn test_single_byte_diff_returns_tampered() {
        let disk = make_page(0x00, 0x1000);
        let mut mem = disk.clone();
        mem[42] = 0xFF; // flip one byte
        assert_eq!(check_integrity(&disk, &mem), ModuleStatus::Tampered);
    }

    #[test]
    fn test_diff_in_second_page_returns_tampered() {
        let disk = make_page(0x00, 0x3000);
        let mut mem = disk.clone();
        mem[0x1001] = 0xDE; // second page
        assert_eq!(check_integrity(&disk, &mem), ModuleStatus::Tampered);
    }

    #[test]
    fn test_all_pages_differ_returns_tampered() {
        let disk = make_page(0x00, 0x3000);
        let mem = make_page(0xFF, 0x3000);
        assert_eq!(check_integrity(&disk, &mem), ModuleStatus::Tampered);
    }

    // --- Length mismatch: compare_len = min(disk, mem) ---

    #[test]
    fn test_mem_longer_than_disk_ok_within_overlap() {
        // disk is 1 page, mem is 2 pages — only 1 page is compared
        let disk = make_page(0xAA, 0x1000);
        let mem = make_page(0xAA, 0x2000); // second page is never checked
        assert_eq!(check_integrity(&disk, &mem), ModuleStatus::Ok);
    }

    #[test]
    fn test_disk_longer_than_mem_ok_within_overlap() {
        let disk = make_page(0xBB, 0x2000);
        let mem = make_page(0xBB, 0x1000);
        assert_eq!(check_integrity(&disk, &mem), ModuleStatus::Ok);
    }

    #[test]
    fn test_mem_longer_diff_in_extra_region_still_ok() {
        // Difference only in mem's extra bytes beyond disk — not compared
        let disk = make_page(0x00, 0x1000);
        let mut mem = make_page(0x00, 0x2000);
        mem[0x1500] = 0xFF; // beyond disk.len(), never reached
        assert_eq!(check_integrity(&disk, &mem), ModuleStatus::Ok);
    }

    #[test]
    fn test_length_mismatch_diff_in_overlap_returns_tampered() {
        let disk = make_page(0x00, 0x2000);
        let mut mem = make_page(0x00, 0x3000);
        mem[0x0010] = 0x01; // within overlap — caught
        assert_eq!(check_integrity(&disk, &mem), ModuleStatus::Tampered);
    }
}
