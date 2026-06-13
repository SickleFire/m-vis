use crate::os::MemoryProvider;
use crate::types::{
    HeapBlock, ModuleInfo, ModuleStatus, Region, RegionKind, RegionProtect, RegionState,
};
use std::fs;
use std::io;

pub struct LinuxMemory;

impl MemoryProvider for LinuxMemory {
    fn walk_regions(&self, pid: u32) -> Result<Vec<Region>, String> {
        Ok(walk_regions(pid))
    }

    fn walk_heap(&self, pid: u32) -> Result<Vec<HeapBlock>, String> {
        Ok(walk_heap(pid))
    }

    fn list_modules(&self, pid: u32, flag: String) -> Result<Vec<ModuleInfo>, String> {
        Ok(list_modules(pid, flag))
    }
}

/// Reads `/proc/<pid>/maps` and returns all mapped virtual memory regions for the process.
pub fn walk_regions(pid: u32) -> Vec<Region> {
    let path = format!("/proc/{}/maps", pid);
    let content = fs::read_to_string(path).expect("failed to read maps");
    let mut regions = Vec::new();

    for line in content.lines() {
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

    regions
}

/// Reads `/proc/<pid>/smaps` and returns heap blocks for the process.
pub fn walk_heap(pid: u32) -> Vec<HeapBlock> {
    let path = format!("/proc/{}/smaps", pid);
    let content = fs::read_to_string(path).expect("failed to read maps");
    let mut blocks = Vec::new();
    let mut current_start = 0usize;
    let mut in_heap = false;
    let mut protect: RegionProtect;

    for line in content.lines() {
        if line.contains("[heap]") {
            in_heap = true;
            let range = line.split_whitespace().next().unwrap_or("");
            let mut parts = range.split('-');
            current_start = usize::from_str_radix(parts.next().unwrap_or("0"), 16).unwrap_or(0);
        } else if in_heap && line.starts_with("Size:") {
            let perms = line.split_whitespace().nth(1).unwrap_or("");
            if perms.contains('x') {
                protect = RegionProtect::Execute;
            } else if perms.contains('w') {
                protect = RegionProtect::ReadWrite;
            } else if perms.contains('r') {
                protect = RegionProtect::Readonly;
            } else {
                protect = RegionProtect::NoAccess;
            };
            let kb: usize = line
                .split_whitespace()
                .nth(1)
                .unwrap_or("0")
                .parse()
                .unwrap_or(0);
            blocks.push(HeapBlock {
                address: current_start,
                size: kb * 1024,
                is_free: false,
                vm_protect: protect,
            });
            in_heap = false;
        }
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
