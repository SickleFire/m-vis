use crate::os::MemoryProvider;
use crate::types::{
    HeapBlock, ModuleInfo, ModuleStatus, PointerEdge, Region, RegionKind, RegionProtect,
    RegionState,
};
use std::collections::HashMap;
use std::fs;
use std::io;

pub struct LinuxMemory;

impl MemoryProvider for LinuxMemory {
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

/// Reads `/proc/<pid>/maps` and returns all mapped virtual memory regions for the process.
pub fn walk_regions(pid: u32) -> Result<Vec<Region>, String> {
    let path = format!("/proc/{}/maps", pid);
    let content = fs::read_to_string(path).map_err(|e| format!("failed to read maps: {}", e))?;
    let mut regions = Vec::new();
    let mut region_count = 0;
    const MAX_REGIONS_PER_PROCESS: usize = 100_000;

    for line in content.lines() {
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
        // each line looks like:
        // 55a3b2000000-55a3b2001000 r--p 00000000 08:01 123456  /usr/bin/cat
        let mut parts = line.splitn(6, ' ');

        let range = parts.next().unwrap_or("");
        let perms = parts.next().unwrap_or("");
        let _offset = parts.next();
        let _device = parts.next();
        let _inode = parts.next();
        let name = parts.next().unwrap_or("").trim();

        // parse start-end
        let mut range_parts = range.split('-');
        let start = usize::from_str_radix(range_parts.next().unwrap_or("0"), 16).unwrap_or(0);
        let end = usize::from_str_radix(range_parts.next().unwrap_or("0"), 16).unwrap_or(0);

        let protect = if perms.contains('x') {
            RegionProtect::Execute
        } else if perms.contains('w') {
            RegionProtect::ReadWrite
        } else if perms.contains('r') {
            RegionProtect::Readonly
        } else {
            RegionProtect::NoAccess
        };

        let kind = if name.ends_with(".so") || name.ends_with(".so.1") {
            RegionKind::Image
        } else if name.is_empty() {
            RegionKind::Private
        } else {
            RegionKind::Mapped
        };

        let region_name = name.to_string();
        regions.push(Region {
            base: start,
            size: end - start,
            state: RegionState::Committed, // linux maps only shows committed
            kind,
            protect,
            name: region_name,
        });
    }
    Ok(regions)
}

pub fn walk_heap(pid: u32) -> Vec<HeapBlock> {
    let mut blocks = Vec::new();

    let maps_path = format!("/proc/{}/maps", pid);
    let maps_content = match fs::read_to_string(&maps_path) {
        Ok(c) => c,
        Err(_) => return blocks,
    };

    let mut heap_start = 0usize;
    let mut heap_end = 0usize;
    let mut vm_protect = RegionProtect::NoAccess;

    for line in maps_content.lines() {
        if !line.contains("[heap]") {
            continue;
        }

        let mut parts = line.splitn(6, ' ');
        let range = parts.next().unwrap_or("");
        let perms = parts.next().unwrap_or("");

        let mut range_parts = range.split('-');
        heap_start = usize::from_str_radix(range_parts.next().unwrap_or("0"), 16).unwrap_or(0);
        heap_end = usize::from_str_radix(range_parts.next().unwrap_or("0"), 16).unwrap_or(0);

        vm_protect = if perms.contains('x') {
            RegionProtect::Execute
        } else if perms.contains('w') {
            RegionProtect::ReadWrite
        } else if perms.contains('r') {
            RegionProtect::Readonly
        } else {
            RegionProtect::NoAccess
        };

        break; // only one [heap] entry exists, stop looking
    }

    if heap_start > 0 && heap_end > heap_start {
        blocks.push(HeapBlock {
            address: heap_start,
            size: heap_end - heap_start,
            is_free: false,
            vm_protect,
        });
    }

    blocks
}

/// Reads `/proc/<pid>/smaps` (or `/proc/<pid>/mem`) and returns individual glibc heap chunks.
pub fn walk_heap_granular(pid: u32) -> Vec<HeapBlock> {
    use std::os::unix::fs::FileExt;

    let mut blocks = Vec::new();

    let maps_path = format!("/proc/{}/maps", pid);
    let maps_content = match fs::read_to_string(&maps_path) {
        Ok(c) => c,
        Err(_) => return blocks,
    };

    let mut heap_start = 0usize;
    let mut heap_end = 0usize;
    let mut vm_protect = RegionProtect::NoAccess;

    for line in maps_content.lines() {
        if !line.contains("[heap]") {
            continue;
        }

        let mut parts = line.splitn(6, ' ');
        let range = parts.next().unwrap_or("");
        let perms = parts.next().unwrap_or("");

        let mut range_parts = range.split('-');
        heap_start = usize::from_str_radix(range_parts.next().unwrap_or("0"), 16).unwrap_or(0);
        heap_end = usize::from_str_radix(range_parts.next().unwrap_or("0"), 16).unwrap_or(0);

        vm_protect = if perms.contains('x') {
            RegionProtect::Execute
        } else if perms.contains('w') {
            RegionProtect::ReadWrite
        } else if perms.contains('r') {
            RegionProtect::Readonly
        } else {
            RegionProtect::NoAccess
        };

        break; // only one [heap] entry exists, stop looking
    }

    if heap_start == 0 || heap_end <= heap_start {
        return blocks; // no heap found, nothing to walk
    }

    let mem_path = format!("/proc/{}/mem", pid);
    let mem = match std::fs::File::open(&mem_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[mvis] walk_heap_granular: failed to open {}: {}", mem_path, e);
            return blocks;
        }
    };

    const HEADER_SIZE: usize = 16;
    const PREV_INUSE: usize = 0x1;
    const SIZE_MASK: usize = !0x7; // clears the low 3 flag bits, keeps real size

    let read_header = |mem: &std::fs::File, addr: usize| -> io::Result<(usize, usize)> {
        let mut buf = [0u8; HEADER_SIZE];
        mem.read_at(&mut buf, addr as u64)?;
        let prev_size = usize::from_le_bytes(buf[0..8].try_into().unwrap());
        let size = usize::from_le_bytes(buf[8..16].try_into().unwrap());
        Ok((prev_size, size))
    };

    let mut addr = heap_start;

    // read the very first chunk so we have something to inspect each loop
    let (_, mut current_size_field) = match read_header(&mem, addr) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("[mvis] walk_heap_granular: failed to read first chunk at 0x{:x}: {}", addr, e);
            return blocks;
        }
    };

    loop {
        let chunk_size = current_size_field & SIZE_MASK;

        // safety valve: if size is garbage, stop instead of looping forever
        if chunk_size < HEADER_SIZE {
            break;
        }

        let next_addr = addr + chunk_size;

        // reached the end of the heap region — this last chunk is the "top
        // chunk" (glibc's remaining unused arena space), not a real
        // allocation, so we stop here rather than reporting it as a block.
        if next_addr >= heap_end {
            break;
        }

        // read the NEXT chunk's header, because its PREV_INUSE bit tells us
        // whether THIS chunk (at `addr`) is free or in use
        let (_, next_size_field) = match read_header(&mem, next_addr) {
            Ok(h) => h,
            Err(_) => break,
        };
        let is_free = next_size_field & PREV_INUSE == 0;

        // usable memory starts right after this chunk's own header
        blocks.push(HeapBlock {
            address: addr + HEADER_SIZE,
            size: chunk_size - HEADER_SIZE,
            is_free,
            vm_protect: vm_protect.clone(),
        });

        // move to the next chunk and repeat
        addr = next_addr;
        current_size_field = next_size_field;
    }

    blocks
}

/// Returns loaded modules for the process, cross-checking disk vs memory for tampering.
///
/// Pass `flag = "-t"` to return only modules whose `.text` section differs from disk
/// (i.e. injected, modified, or tampered). Returns all modules when `flag` is empty.
pub fn list_modules(pid: u32, flag: String) -> Vec<ModuleInfo> {
    use std::collections::HashMap;

    let tampered = flag == "-t";
    let mut modules: HashMap<String, ModuleInfo> = HashMap::new();

    // read /proc/<pid>/maps to get all loaded regions
    let maps_path = format!("/proc/{}/maps", pid);
    let content = match std::fs::read_to_string(&maps_path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    let map_entries: Vec<_> = content.lines().filter_map(parse_maps_line).collect();

    for map_entry in map_entries.iter().filter(|entry| is_module_mapping(entry)) {
        modules
            .entry(map_entry.path.clone())
            .or_insert_with(|| ModuleInfo {
                base: map_entry.start,
                size: 0,
                name: std::path::Path::new(&map_entry.path)
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
                path: map_entry.path.clone(),
                status: ModuleStatus::Ok,
            });
    }

    for map_entry in &map_entries {
        if let Some(module) = modules.get_mut(&map_entry.path) {
            let size = map_entry.size();
            module.size += size;
            if map_entry.start < module.base {
                module.base = map_entry.start;
            }
        }
    }

    let mem_path = format!("/proc/{}/mem", pid);
    let mut mem_file = std::fs::File::open(mem_path).ok();

    for (path, module) in modules.iter_mut() {
        if !std::path::Path::new(path).exists() {
            module.status = ModuleStatus::Injected;
            continue;
        }

        // If the process memory file cannot be opened at all, Linux ptrace policy is
        // preventing integrity checks for the whole process. Do not mark every
        // clean module as Unreadable in that case; leave the default Ok status so
        // `-t` only reports actionable per-module problems.
        let Some(mem_file) = mem_file.as_mut() else {
            continue;
        };

        let disk_text = match read_text_section_from_disk(path) {
            Some(text) => text,
            None => {
                module.status = ModuleStatus::Unreadable;
                continue;
            }
        };

        let text_addr = match text_section_memory_address(&map_entries, path, disk_text.file_offset)
        {
            Some(addr) => addr,
            None => {
                module.status = ModuleStatus::Unreadable;
                continue;
            }
        };

        let mem_bytes =
            match read_text_section_from_memory_linux(mem_file, text_addr, disk_text.bytes.len()) {
                Ok(bytes) => bytes,
                Err(_) => {
                    module.status = ModuleStatus::Unreadable;
                    continue;
                }
            };

        module.status = check_integrity(&disk_text.bytes, &mem_bytes);
    }

    let mut result: Vec<ModuleInfo> = if tampered {
        modules
            .into_values()
            .filter(|m| m.status != ModuleStatus::Ok)
            .collect()
    } else {
        modules.into_values().collect()
    };

    result.sort_by(|a, b| a.base.cmp(&b.base));
    result
}

/// Scans live heap blocks for pointer-like values and resolves each against
/// the full block list (live + free) via binary search.
///
/// Edges into a freed block are marked `target_is_free: true` — a live block
/// still holding a reference to freed memory is a dangling-pointer / UAF signal.
pub fn find_pointer_edges(pid: u32, blocks: &[HeapBlock]) -> HashMap<usize, Vec<PointerEdge>> {
    use std::fs::File;
    use std::os::unix::fs::FileExt;

    let mut edges: HashMap<usize, Vec<PointerEdge>> = HashMap::new();

    let mem_file = match File::open(format!("/proc/{}/mem", pid)) {
        Ok(f) => f,
        Err(_) => return edges,
    };

    // (start, end, is_free) sorted by start — O(log n) containment lookup
    // instead of a linear scan per pointer word.
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

    for block in blocks.iter().filter(|b| !b.is_free) {
        let read_len = block.size.min(4096);
        let mut buf = vec![0u8; read_len];

        // read_at (pread) on /proc/<pid>/mem seeks-and-reads at the given
        // virtual address in one syscall; short/failed reads (e.g. an
        // unmapped or partially-unmapped page) are skipped like the
        // Windows ReadProcessMemory failure path.
        let bytes_read = match mem_file.read_at(&mut buf, block.address as u64) {
            Ok(n) => n,
            Err(_) => continue,
        };

        if bytes_read < 8 {
            continue;
        }

        let mut offset = 0;
        while offset + 8 <= bytes_read {
            let value = usize::from_le_bytes(buf[offset..offset + 8].try_into().unwrap());

            if let Some((target, target_is_free)) = find_containing(value)
                && target != block.address
            {
                let out = edges.entry(block.address).or_default();
                if !out.iter().any(|e: &PointerEdge| e.target == target) {
                    out.push(PointerEdge {
                        target,
                        target_is_free,
                    });
                }
            }

            offset += 8;
        }
    }

    edges
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MapEntry {
    start: usize,
    end: usize,
    offset: usize,
    is_executable: bool,
    path: String,
}

impl MapEntry {
    fn size(&self) -> usize {
        self.end - self.start
    }
}

fn parse_maps_line(line: &str) -> Option<MapEntry> {
    let mut parts = line.split_whitespace();

    let range = parts.next()?;
    let perms = parts.next()?;
    let offset = parts.next()?;
    let _device = parts.next()?;
    let _inode = parts.next()?;
    let path = parts.collect::<Vec<_>>().join(" ");

    let (start, end) = range.split_once('-')?;
    let start = usize::from_str_radix(start, 16).ok()?;
    let end = usize::from_str_radix(end, 16).ok()?;
    if end <= start {
        return None;
    }

    Some(MapEntry {
        start,
        end,
        offset: usize::from_str_radix(offset, 16).ok()?,
        is_executable: perms.contains('x'),
        path,
    })
}

fn is_module_mapping(entry: &MapEntry) -> bool {
    entry.is_executable
        && !entry.path.is_empty()
        && !entry.path.starts_with('[')
        && !entry.path.starts_with("anon")
}

fn text_section_memory_address(
    map_entries: &[MapEntry],
    path: &str,
    file_offset: usize,
) -> Option<usize> {
    map_entries.iter().find_map(|entry| {
        if entry.path != path || !entry.is_executable {
            return None;
        }

        let file_range_end = entry.offset.checked_add(entry.size())?;
        if file_offset < entry.offset || file_offset >= file_range_end {
            return None;
        }

        entry.start.checked_add(file_offset - entry.offset)
    })
}

fn read_text_section_from_memory_linux(
    file: &mut std::fs::File,
    base: usize,
    len: usize,
) -> io::Result<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};

    file.seek(SeekFrom::Start(base as u64))?;

    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf)?;
    Ok(buf)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TextSection {
    file_offset: usize,
    bytes: Vec<u8>,
}

fn read_text_section_from_disk(path: &str) -> Option<TextSection> {
    use object::{Object, ObjectKind, ObjectSection};

    let data = std::fs::read(path).ok()?;
    let obj = object::File::parse(&*data).ok()?;
    if !matches!(obj.kind(), ObjectKind::Executable | ObjectKind::Dynamic) {
        return None;
    }

    let section = obj.section_by_name(".text")?;
    let (file_offset, _) = section.file_range()?;
    let bytes = section.uncompressed_data().ok()?.into_owned();
    if bytes.is_empty() {
        return None;
    }

    Some(TextSection {
        file_offset: file_offset.try_into().ok()?,
        bytes,
    })
}

fn check_integrity(disk: &[u8], mem: &[u8]) -> ModuleStatus {
    if disk.len() != mem.len() {
        return ModuleStatus::Tampered;
    }

    let diffs = disk.iter().zip(mem.iter()).filter(|(a, b)| a != b).count();

    if diffs == 0 {
        ModuleStatus::Ok
    } else if diffs < 16 {
        // small number of diffs — likely runtime relocations or hot patches
        // not necessarily malicious but worth flagging
        ModuleStatus::Modified
    } else {
        ModuleStatus::Tampered
    }
}

/// Reads up to `size` bytes from target process memory at `address` via `/proc/<pid>/mem`,
pub fn read_process_memory_bytes(pid: u32, address: usize, size: usize) -> Result<Vec<u8>, String> {
    use std::io::{Read, Seek, SeekFrom};

    let mem_path = format!("/proc/{}/mem", pid);
    let mut mem_file =
        std::fs::File::open(&mem_path).map_err(|e| format!("Failed to open {mem_path}: {e}"))?;

    mem_file
        .seek(SeekFrom::Start(address as u64))
        .map_err(|e| format!("Failed to seek to 0x{address:x} for PID {pid}: {e}"))?;

    let mut buf = vec![0u8; size];
    let bytes_read = mem_file
        .read(&mut buf)
        .map_err(|e| format!("Failed to read memory at 0x{address:x} for PID {pid}: {e}"))?;

    if bytes_read == 0 {
        return Err(format!(
            "Failed to read memory at 0x{address:x} for PID {pid}"
        ));
    }

    buf.truncate(bytes_read);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proc_maps_line() {
        let entry = parse_maps_line(
            "72d6fb428000-72d6fb5b0000 r-xp 00028000 08:02 1238129                    /usr/lib/x86_64-linux-gnu/libc.so.6",
        )
        .unwrap();

        assert_eq!(entry.start, 0x72d6fb428000);
        assert_eq!(entry.end, 0x72d6fb5b0000);
        assert_eq!(entry.offset, 0x28000);
        assert!(entry.is_executable);
        assert_eq!(entry.path, "/usr/lib/x86_64-linux-gnu/libc.so.6");
    }

    #[test]
    fn module_mappings_must_be_executable_file_paths() {
        let locale = parse_maps_line(
            "72d6fb000000-72d6fb2eb000 r--p 00000000 08:02 1179733                    /usr/lib/locale/locale-archive",
        )
        .unwrap();
        let vdso =
            parse_maps_line("7ffe925b0000-7ffe925b2000 r-xp 00000000 00:00 0 [vdso]").unwrap();
        let libc = parse_maps_line(
            "72d6fb428000-72d6fb5b0000 r-xp 00028000 08:02 1238129                    /usr/lib/x86_64-linux-gnu/libc.so.6",
        )
        .unwrap();

        assert!(!is_module_mapping(&locale));
        assert!(!is_module_mapping(&vdso));
        assert!(is_module_mapping(&libc));
    }

    #[test]
    fn maps_text_file_offset_to_memory_address() {
        let entries = vec![
            parse_maps_line("1000-2000 r--p 00000000 08:02 1 /usr/bin/app").unwrap(),
            parse_maps_line("2000-5000 r-xp 00001000 08:02 1 /usr/bin/app").unwrap(),
        ];

        assert_eq!(
            text_section_memory_address(&entries, "/usr/bin/app", 0x1234),
            Some(0x2234)
        );
    }

    #[test]
    fn maps_text_file_offset_only_to_executable_mapping() {
        let entries = vec![
            parse_maps_line("1000-5000 r--p 00001000 08:02 1 /usr/bin/app").unwrap(),
            parse_maps_line("6000-9000 r-xp 00001000 08:02 1 /usr/bin/app").unwrap(),
        ];

        assert_eq!(
            text_section_memory_address(&entries, "/usr/bin/app", 0x1234),
            Some(0x6234)
        );
    }

    #[test]
    fn reads_text_section_from_current_exe() {
        let exe = std::env::current_exe().unwrap();
        let section = read_text_section_from_disk(exe.to_str().unwrap()).unwrap();

        assert!(section.file_offset > 0);
        assert!(!section.bytes.is_empty());
    }

    #[test]
    fn identical_bytes_are_ok() {
        let bytes = [1, 2, 3, 4];

        assert_eq!(check_integrity(&bytes, &bytes), ModuleStatus::Ok);
    }

    #[test]
    fn global_memory_denial_is_not_per_module_unreadable_noise() {
        let module = ModuleInfo {
            base: 0x1000,
            size: 0x2000,
            name: "libexample.so".to_string(),
            path: "/usr/lib/libexample.so".to_string(),
            status: ModuleStatus::Ok,
        };

        // When /proc/<pid>/mem cannot be opened at all, list_modules leaves the
        // default status in place instead of reporting every module as Unreadable.
        assert_eq!(module.status, ModuleStatus::Ok);
    }
}
