use crate::os::MemoryProvider;
use crate::types::{
    HeapBlock, ModuleInfo, ModuleStatus, Region, RegionKind, RegionProtect, RegionState,
};
use mach2::kern_return::KERN_SUCCESS;
use mach2::port::{mach_port_name_t, mach_port_t};
use mach2::traps::mach_task_self;
use mach2::vm::mach_vm_region;
use mach2::vm_prot::{VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE};
use mach2::vm_region::{vm_region_basic_info_64, vm_region_info_t, VM_REGION_BASIC_INFO_64};
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
    fn get_task_port(&self, pid: u32) -> Result<mach_port_t, &'static str> {
        let mut task: mach_port_t = 0;
        unsafe {
            let res = task_for_pid(mach_task_self(), pid as libc::pid_t, &mut task);
            if res != KERN_SUCCESS {
                return Err("Failed to get task port. macOS requires 'sudo' or 'task_for_pid-allow' entitlement to inspect processes.");
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
    fn walk_regions(&self, pid: u32) -> Vec<Region> {
        let task = match self.get_task_port(pid) {
            Ok(t) => t,
            Err(_) => {
                return vec![];
            }
        };

        let mut regions = Vec::new();
        let mut address: mach2::vm_types::mach_vm_address_t = 0;

        loop {
            let mut size: mach2::vm_types::mach_vm_size_t = 0;
            let mut info: vm_region_basic_info_64 = unsafe { mem::zeroed() };
            let mut info_count = mem::size_of::<vm_region_basic_info_64>() as mach2::message::mach_msg_type_number_t
                / mem::size_of::<i32>() as mach2::message::mach_msg_type_number_t;
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
                break; // End of address space or error
            }

            let state = RegionState::Committed;

            let protect = match (
                info.protection & VM_PROT_READ != 0,
                info.protection & VM_PROT_WRITE != 0,
                info.protection & VM_PROT_EXECUTE != 0,
            ) {
                (false, false, false) => RegionProtect::Guard, // On macOS, unmapped/protected gaps are guards
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
                if name.contains(".dylib") || name.contains("Frameworks") || name.contains("dyld") {
                    RegionKind::Mapped
                } else {
                    RegionKind::Image
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

        regions
    }

    fn walk_heap(&self, pid: u32) -> Vec<HeapBlock> {
        let regions = self.walk_regions(pid);
        let mut heap_blocks = Vec::new();
        let mut is_after_guard = false;

        for r in regions {
            if r.protect == RegionProtect::Guard {
                is_after_guard = true;
                continue;
            }

            if r.kind == RegionKind::Private
                && r.protect == RegionProtect::ReadWrite
                && r.name.is_empty()
            {
                if is_after_guard {
                    // Likely a thread stack, skip it
                    is_after_guard = false;
                    continue;
                }

                heap_blocks.push(HeapBlock {
                    address: r.base,
                    size: r.size,
                    is_free: false,
                    vm_protect: r.protect.clone(),
                });
            }

            is_after_guard = false;
        }
        heap_blocks
    }

    fn list_modules(&self, pid: u32, _flag: String) -> Vec<ModuleInfo> {
        let regions = self.walk_regions(pid);
        let mut modules = Vec::new();
        let mut seen = HashSet::new();

        for r in regions {
            if !r.name.is_empty()
                && (r.kind == RegionKind::Image
                    || r.name.ends_with(".dylib")
                    || r.name.ends_with(".bundle")
                    || r.name.contains("dyld_shared_cache")
                    || r.name.contains("Frameworks")
                    || r.name.contains("dyld"))
            {
                if seen.insert(r.name.clone()) {
                    let path = Path::new(&r.name);
                    let file_name = path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string();

                    let is_injected = false; // Advanced heuristic later

                    modules.push(ModuleInfo {
                        base: r.base,
                        size: r.size,
                        name: file_name,
                        path: r.name,
                        status: if is_injected {
                            ModuleStatus::Injected
                        } else {
                            ModuleStatus::Ok
                        },
                    });
                }
            }
        }
        modules
    }
}
