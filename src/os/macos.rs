use crate::os::MemoryProvider;
use crate::types::{
    HeapBlock, ModuleInfo, ModuleStatus, Region, RegionKind, RegionProtect, RegionState,
};
use mach2::kern_return::KERN_SUCCESS;
use mach2::port::{mach_port_name_t, mach_port_t};
use mach2::traps::mach_task_self;
use mach2::vm::mach_vm_region;
use mach2::vm_prot::{VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE};
use mach2::vm_region::{VM_REGION_BASIC_INFO_64, vm_region_basic_info_64, vm_region_info_t};
use mach2::vm_types::natural_t;
use std::collections::HashSet;
use std::mem;
use std::path::Path;

unsafe extern "C" {
    fn task_for_pid(
        target_tport: mach_port_name_t,
        pid: libc::pid_t,
        t: *mut mach_port_t,
    ) -> mach2::kern_return::kern_return_t;
}

pub struct MacMemory;

impl MacMemory {
    pub fn get_task_port(&self, pid: u32) -> Result<mach_port_t, String> {
        let mut task: mach_port_t = 0;
        unsafe {
            let res = task_for_pid(mach_task_self(), pid as libc::pid_t, &mut task);
            if res != KERN_SUCCESS {
                return Err(format!(
                    "task_for_pid failed (kern_return={}). \
                     This binary is not signed with the 'com.apple.security.cs.debugger' entitlement. \
                     Run: codesign --force --sign - --entitlements mvis.entitlements target/debug/mvis\n\
                     Note: Apple platform apps (Safari, WebKit) and Hardened Runtime apps (WhatsApp) \
                     remain protected even with the entitlement.",
                    res
                ));
            }
        }
        Ok(task)
    }

    fn get_region_name(&self, pid: u32, address: usize) -> String {
        match libproc::libproc::proc_pid::regionfilename(pid as i32, address as u64) {
            Ok(name) => name,
            Err(_) => String::new(),
        }
    }
}

impl MemoryProvider for MacMemory {
    fn walk_regions(&self, pid: u32) -> Result<Vec<Region>, String> {
        let task = self.get_task_port(pid)?;

        let mut regions = Vec::new();
        let mut address: mach2::vm_types::mach_vm_address_t = 1; // start at 1 to skip the zero page

        loop {
            let mut size: mach2::vm_types::mach_vm_size_t = 0;
            let mut info: vm_region_basic_info_64 = unsafe { mem::zeroed() };
            // FIX: use natural_t (u32) as the unit, not i32
            let mut info_count = (mem::size_of::<vm_region_basic_info_64>()
                / mem::size_of::<natural_t>())
                as mach2::message::mach_msg_type_number_t;
            let mut object_name: mach_port_t = 0;

            let res = unsafe {
                mach_vm_region(
                    task,
                    &mut address,
                    &mut size,
                    VM_REGION_BASIC_INFO_64,
                    &mut info as *mut _ as vm_region_info_t,
                    &mut info_count,
                    &mut object_name,
                )
            };

            if res != KERN_SUCCESS {
                break;
            }

            // FIX: guard against zero-size regions causing an infinite loop
            if size == 0 {
                address = address.saturating_add(1);
                continue;
            }

            let state = RegionState::Committed;

            // FIX: VM_PROT_NONE is not the same as a guard page on macOS.
            // We label it NoAccess and let classify() in scan.rs sort it out.
            let protect = match (
                info.protection & VM_PROT_READ != 0,
                info.protection & VM_PROT_WRITE != 0,
                info.protection & VM_PROT_EXECUTE != 0,
            ) {
                (false, false, false) => RegionProtect::NoAccess,
                (true, false, false) => RegionProtect::Readonly,
                (true, true, false) => RegionProtect::ReadWrite,
                (_, _, true) => RegionProtect::Execute,
                _ => RegionProtect::Other,
            };

            let mut name = self.get_region_name(pid, address as usize);

            if name.is_empty() && info.shared != 0 {
                if info.protection & VM_PROT_EXECUTE != 0 {
                    name = "dyld_shared_cache".to_string();
                } else {
                    name = "shared_memory".to_string();
                }
            }

            let refined_kind = if !name.is_empty() {
                if name.contains(".dylib")
                    || name.contains(".bundle")
                    || name.contains("Frameworks")
                    || name.contains("dyld")
                    || name.contains("dyld_shared_cache")
                {
                    RegionKind::Image
                } else {
                    RegionKind::Mapped
                }
            } else if info.shared != 0 {
                RegionKind::Mapped
            } else {
                RegionKind::Private
            };

            regions.push(Region {
                base: address as usize,
                size: size as usize,
                state,
                kind: refined_kind,
                protect,
                name,
            });

            address = address.saturating_add(size);
        }

        Ok(regions)
    }

    fn walk_heap(&self, pid: u32) -> Result<Vec<HeapBlock>, String> {
        let regions = self.walk_regions(pid)?;
        let mut heap_blocks = Vec::new();

        // On macOS, guard pages follow the live stack (low→high iteration means
        // guard comes AFTER live stack). We track the previous region's protection
        // to detect the [live stack] → [guard] pattern and skip accordingly.
        for r in &regions {
            if r.protect == RegionProtect::NoAccess {
                continue;
            }

            if r.kind == RegionKind::Private
                && r.protect == RegionProtect::ReadWrite
                && r.name.is_empty()
            {
                heap_blocks.push(HeapBlock {
                    address: r.base,
                    size: r.size,
                    is_free: false,
                    vm_protect: r.protect.clone(),
                });
            }
        }

        // Apply lookahead fix: remove the last pushed block if the current is NoAccess.
        // We will just recreate the list to be clean.
        let mut final_heap_blocks = Vec::new();
        for i in 0..regions.len() {
            let r = &regions[i];
            if r.kind == RegionKind::Private
                && r.protect == RegionProtect::ReadWrite
                && r.name.is_empty()
            {
                // Lookahead
                let mut is_stack = false;
                if i + 1 < regions.len() {
                    let next = &regions[i + 1];
                    if next.protect == RegionProtect::NoAccess {
                        is_stack = true;
                    }
                }
                if !is_stack {
                    final_heap_blocks.push(HeapBlock {
                        address: r.base,
                        size: r.size,
                        is_free: false,
                        vm_protect: r.protect.clone(),
                    });
                }
            }
        }

        Ok(final_heap_blocks)
    }

    fn list_modules(&self, pid: u32, _flag: String) -> Result<Vec<ModuleInfo>, String> {
        let regions = self.walk_regions(pid)?;
        let mut modules = Vec::new();
        let mut seen = HashSet::new();

        for r in regions {
            let is_module = r.kind == RegionKind::Image
                || r.name.ends_with(".dylib")
                || r.name.ends_with(".bundle")
                || r.name.contains("dyld_shared_cache")
                || r.name.contains("Frameworks")
                || r.name.contains("dyld");

            if !r.name.is_empty() && is_module {
                if seen.insert(r.name.clone()) {
                    let path = Path::new(&r.name);
                    let file_name = path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string();

                    modules.push(ModuleInfo {
                        base: r.base,
                        size: r.size,
                        name: file_name,
                        path: r.name,
                        status: ModuleStatus::Ok,
                    });
                }
            }
        }
        Ok(modules)
    }
}
