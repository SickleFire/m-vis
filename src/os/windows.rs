use windows::Win32::System::ProcessStatus::GetModuleFileNameExW;
use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_PRIVATE, MEM_RESERVE, MEM_IMAGE, MEM_MAPPED, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_GUARD, PAGE_READWRITE, PAGE_READONLY, VirtualQueryEx
};

use crate::types::{HeapBlock, Region, RegionKind, RegionProtect, RegionState};

pub fn walk_regions(pid: u32) -> Vec<Region> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid).expect("failed to load process") };
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
        if written == 0 { break; }
        
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
            protect: if mbi.Protect.contains(PAGE_GUARD){
                RegionProtect::Guard
            }else if mbi.Protect.contains(PAGE_EXECUTE_READ)
                  || mbi.Protect.contains(PAGE_EXECUTE){
                    RegionProtect::Execute
            }else if mbi.Protect.contains(PAGE_READWRITE){
                RegionProtect::ReadWrite
            }else if mbi.Protect.contains(PAGE_READONLY) {
                RegionProtect::Readonly
            }else {
                RegionProtect::Other
            },
            name: if mbi.Type == MEM_IMAGE {
                let hmodule = HMODULE(mbi.AllocationBase as *mut _);
                let mut buf = vec![0u16; 260];  // MAX_PATH
                let len = unsafe {
                    GetModuleFileNameExW(Some(handle), Some(hmodule), &mut buf)
                };
                if len > 0 {
                    String::from_utf16_lossy(&buf[..len as usize])
                } else {
                    String::new()
                }
            } else {
                String::new()
            }
        };
        regions.push(region);
        addr = addr.saturating_add(mbi.RegionSize);
        if addr == 0 { break; }
    }
    regions
}

pub fn walk_heap(pid: u32) -> Vec<HeapBlock>{
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Heap32ListFirst, Heap32ListNext,
        Heap32First, Heap32Next, HEAPLIST32, HEAPENTRY32,
        TH32CS_SNAPHEAPLIST, LF32_FREE,
    };
    let mut blocks = Vec::new();

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST, pid)
            .expect("failed to create snapshot");

        let mut hl = HEAPLIST32::default();
        hl.dwSize = std::mem::size_of::<HEAPLIST32>() as usize;

        // walk each heap
        if Heap32ListFirst(snapshot, &mut hl).is_ok() {
            loop {
                // walk each block in this heap
                let mut he = HEAPENTRY32::default();
                he.dwSize = std::mem::size_of::<HEAPENTRY32>() as usize;

                if Heap32First(&mut he, pid, hl.th32HeapID).is_ok() {
                    loop {
                        let is_free = he.dwFlags == LF32_FREE;
                        blocks.push(HeapBlock { address: he.dwAddress, size: he.dwBlockSize, is_free });
                        if Heap32Next(&mut he).is_err() { break; }
                    }
                }

                if Heap32ListNext(snapshot, &mut hl).is_err() { break; }
            }
        }
    }
    blocks
}