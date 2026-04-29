use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct StackFrame {
    pub instruction_pointer: usize,
    pub base_pointer:        usize,
    pub return_address:      usize,
    /// Resolved as "region_name+0x<offset>" using your existing Region vec
    pub symbol:              String,
}

#[derive(Debug, Serialize)]
pub struct StackTrace {
    pub pid:    u32,
    pub frames: Vec<StackFrame>,
}

// ── platform dispatch ────────────────────────────────────────────────────────

impl StackTrace {
    pub fn capture(pid: u32, regions: &[crate::types::Region]) -> Result<Self, String> {
        #[cfg(target_os = "linux")]
        return linux::capture(pid, regions);

        #[cfg(target_os = "windows")]
        return windows::capture(pid, regions);

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        Err("stack trace not supported on this platform".into())
    }
}

// ── symbol resolution (shared) ───────────────────────────────────────────────

pub fn resolve(ip: usize, regions: &[crate::types::Region]) -> String {
    regions
        .iter()
        .find(|r| ip >= r.base && ip < r.base + r.size)
        .map(|r| {
            let label = if r.name.is_empty() { "<anonymous>" } else { &r.name };
            format!("{}+0x{:x}", label, ip - r.base)
        })
        .unwrap_or_else(|| format!("0x{:x}", ip))
}

// ── Linux ────────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod linux {
    use super::{resolve, StackFrame, StackTrace};
    use nix::sys::ptrace;
    use nix::sys::wait::{waitpid, WaitStatus};
    use nix::unistd::Pid;

    pub fn capture(pid: u32, regions: &[crate::types::Region]) -> Result<StackTrace, String> {
        let nix_pid = Pid::from_raw(pid as i32);

        ptrace::attach(nix_pid).map_err(|e| format!("ptrace attach: {e}"))?;
        match waitpid(nix_pid, None).map_err(|e| format!("waitpid: {e}"))? {
            WaitStatus::Stopped(_, _) => {}
            s => return Err(format!("unexpected stop status: {s:?}")),
        }

        let regs = ptrace::getregs(nix_pid).map_err(|e| format!("getregs: {e}"))?;
        let frames = unwind(nix_pid, regs.rip as usize, regs.rsp as usize, regs.rbp as usize, regions);

        ptrace::detach(nix_pid, None).map_err(|e| format!("ptrace detach: {e}"))?;
        Ok(StackTrace { pid, frames })
    }

    fn peek(pid: Pid, addr: usize) -> Option<usize> {
        if addr == 0 || addr % std::mem::align_of::<usize>() != 0 {
            return None;
        }
        
            ptrace::read(pid, addr as *mut libc::c_void)
                .ok()
                .map(|w| w as usize)

    }

    fn resolve_sym(ip: usize, regions: &[crate::types::Region]) -> String {
        use object::{Object, ObjectSection};
        
        let region = regions.iter().find(|r| ip >= r.base && ip < r.base + r.size);
        let (path, map_base) = match region {
            Some(r) if !r.name.is_empty() => (r.name.clone(), r.base),
            _ => return format!("0x{:x}", ip),
        };
    
        let file = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(_) => return format!("{}+0x{:x}", path, ip - map_base),
        };
        let mmap = match unsafe { memmap2::Mmap::map(&file) } {
            Ok(m) => m,
            Err(_) => return format!("{}+0x{:x}", path, ip - map_base),
        };
        let obj = match object::File::parse(&*mmap) {
            Ok(o) => o,
            Err(_) => return format!("{}+0x{:x}", path, ip - map_base),
        };
    
        // find the ELF's own preferred load address from the first LOAD segment
        // for PIE this is 0, for non-PIE it's typically 0x400000
        let elf_load_base: u64 = obj
            .segments()
            .filter_map(|s| {
                use object::ObjectSegment;
                if s.file_range().0 == 0 { Some(s.address()) } else { None }
            })
            .next()
            .unwrap_or(0);
        
        // virtual address in the file = runtime ip - map base + elf load base
        let file_va = (ip - map_base) as u64 + elf_load_base;
        
        let endian = if obj.is_little_endian() {
            gimli::RunTimeEndian::Little
        } else {
            gimli::RunTimeEndian::Big
        };
    
        let load = |id: gimli::SectionId| -> gimli::Result<gimli::EndianSlice<gimli::RunTimeEndian>> {
            let data = obj
                .section_by_name(id.name())
                .and_then(|s| s.uncompressed_data().ok())
                .unwrap_or(std::borrow::Cow::Borrowed(&[]));
            Ok(gimli::EndianSlice::new(
                Box::leak(data.into_owned().into_boxed_slice()),
                endian,
            ))
        };
    
        let dwarf = match gimli::Dwarf::load(load) {
            Ok(d) => d,
            Err(_) => return format!("{}+0x{:x}", path, ip - map_base),
        };
    
        let ctx = match addr2line::Context::from_dwarf(dwarf) {
            Ok(c) => c,
            Err(_) => return format!("{}+0x{:x}", path, ip - map_base),
        };
    
        match ctx.find_frames(file_va).skip_all_loads() {
            Ok(mut iter) => {
                if let Ok(Some(frame)) = iter.next() {
                    let func = frame
                        .function
                        .as_ref()
                        .and_then(|f| f.demangle().ok())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| format!("{}+0x{:x}", path, ip - map_base));
                    let loc = frame
                        .location
                        .as_ref()
                        .map(|l| format!("  {}:{}", l.file.unwrap_or("?"), l.line.unwrap_or(0)))
                        .unwrap_or_default();
                    return format!("{}{}", func, loc);
                }
                format!("{}+0x{:x}", path, ip - map_base)
            }
            Err(_) => format!("{}+0x{:x}", path, ip - map_base),
        }
    }

    fn unwind(
        pid: Pid,
        mut rip: usize,
        mut rsp: usize,
        mut rbp: usize,
        regions: &[crate::types::Region],
    ) -> Vec<StackFrame> {
        let mut frames = Vec::new();

        for _ in 0..128 {
            if rbp == 0 || rbp < rsp { break; }

            let return_address = peek(pid, rbp + 8).unwrap_or(0);
            let symbol = resolve_sym(rip, regions);

            frames.push(StackFrame { instruction_pointer: rip, base_pointer: rbp, return_address, symbol });

            if return_address == 0 { break; }
            let prev_rbp = peek(pid, rbp).unwrap_or(0);
            rip = return_address;
            rsp = rbp + 16;
            rbp = prev_rbp;
        }
        frames
    }
}
