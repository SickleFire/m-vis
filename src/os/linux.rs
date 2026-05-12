use crate::types::{HeapBlock, Region, RegionKind, RegionProtect, RegionState};
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

    for line in content.lines() {
        if line.contains("[heap]") {
            in_heap = true;
            let range = line.split_whitespace().next().unwrap_or("");
            let mut parts = range.split('-');
            current_start = usize::from_str_radix(parts.next().unwrap_or("0"), 16).unwrap_or(0);
        } else if in_heap && line.starts_with("Size:") {
            let perms = line.split_whitespace().next().next().unwrap_or("");
            let protect = if perms.contains('x') {
                RegionProtect::Execute;
            } else if perms.contains('w') {
                RegionProtect::ReadWrite;
            }else if perms.contains('r') {
                RegionProtect::Readonly;
            } else {
                RegionProtect::NoAccess;
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
