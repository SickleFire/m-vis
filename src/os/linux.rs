use crate::types::{HeapBlock, Region, RegionKind, RegionProtect, RegionState, ModuleInfo, ModuleStatus};
use std::fs;

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

    for line in content.lines() {
        // format: address perms offset dev inode pathname
        // 7f1234000-7f1235000 r-xp 00000000 fd:01 123456 /usr/lib/libc.so.6
        let parts: Vec<&str> = line.splitn(6, ' ').collect();
        if parts.len() < 6 { continue; }

        let addr_range = parts[0];
        let perms      = parts[1];
        let path       = parts[5].trim();

        // skip anonymous, pseudo, and non-file regions
        if path.is_empty()
            || path.starts_with('[')
            || path.starts_with("anon")
        {
            continue;
        }

        // parse address range
        let addrs: Vec<&str> = addr_range.split('-').collect();
        if addrs.len() != 2 { continue; }
        let base = match usize::from_str_radix(addrs[0], 16) {
            Ok(a) => a,
            Err(_) => continue,
        };
        let end = match usize::from_str_radix(addrs[1], 16) {
            Ok(a) => a,
            Err(_) => continue,
        };
        let size = end - base;

        let entry = modules.entry(path.to_string()).or_insert(ModuleInfo {
            base,
            size: 0,
            name: std::path::Path::new(path)
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            path: path.to_string(),
            status: ModuleStatus::Ok,
        });

        entry.size += size;
        if base < entry.base {
            entry.base = base;
        }
    }

    // integrity check each module
    for (path, module) in modules.iter_mut() {
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

        // read same range from memory via /proc/<pid>/mem
        let mem_bytes = match read_text_section_from_memory_linux(pid, module.base, disk_bytes.len()) {
            Some(b) => b,
            None => {
                module.status = ModuleStatus::Unreadable;
                continue;
            }
        };

        module.status = check_integrity(&disk_bytes, &mem_bytes);
    }

    let mut result: Vec<ModuleInfo> = if tampered {
        modules.into_values()
            .filter(|m| m.status != ModuleStatus::Ok)
            .collect()
    } else {
        modules.into_values().collect()
    };

    result.sort_by(|a, b| a.base.cmp(&b.base));
    result
}

// on Linux, read process memory via /proc/<pid>/mem
fn read_text_section_from_memory_linux(pid: u32, base: usize, len: usize) -> Option<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};

    let mem_path = format!("/proc/{}/mem", pid);
    let mut file = std::fs::File::open(&mem_path).ok()?;

    // find the .text section offset in the loaded ELF
    // same logic as disk — find the .text section's virtual address
    // then seek to base + (text_vaddr - load_vaddr)
    file.seek(SeekFrom::Start(base as u64)).ok()?;

    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf).ok()?;
    Some(buf)
}

// Linux ELF .text section reader — same interface as Windows version
fn read_text_section_from_disk(path: &str) -> Option<Vec<u8>> {
    use object::{Object, ObjectSection};

    let data = std::fs::read(path).ok()?;
    let obj = object::File::parse(&*data).ok()?;

    let section = obj.section_by_name(".text")?;
    let data = section.uncompressed_data().ok()?;
    Some(data.into_owned())
}

fn check_integrity(disk: &[u8], mem: &[u8]) -> ModuleStatus {
    if disk.len() != mem.len() {
        return ModuleStatus::Tampered;
    }

    let diffs = disk.iter()
        .zip(mem.iter())
        .filter(|(a, b)| a != b)
        .count();

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