//! # Stack Trace Capture
//!
//! Cross-platform stack trace capture for running processes.
//!
//! ## Platform Support
//! - **Linux**: uses `ptrace` to attach, read registers, and walk frames.
//!   Symbol resolution uses DWARF debug info via `gimli` and `addr2line`. (At the moment I cant get it to work)
//! - **Windows**: uses `DbgHelp` (`StackWalk64` + `SymFromAddr`) to walk
//!   frames and resolve symbols from loaded modules.
//!
//! ## Usage
//! ```ignore
//! use mvis::stack_trace::StackTrace;
//!
//! let regions = mvis::os::walk_regions(pid);
//! let trace   = StackTrace::capture(pid, &regions).unwrap();
//! for frame in &trace.frames {
//!     println!("0x{:x}  {}", frame.instruction_pointer, frame.symbol);
//! }
//! ```

use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct StackFrame {
    pub instruction_pointer: usize,
    pub base_pointer: usize,
    pub return_address: usize,
    /// Resolved as "region_name+0x<offset>" using your existing Region vec
    pub symbol: String,
}

#[derive(Debug, Serialize)]
pub struct StackTrace {
    pub pid: u32,
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
            let label = if r.name.is_empty() {
                "<anonymous>"
            } else {
                &r.name
            };
            format!("{}+0x{:x}", label, ip - r.base)
        })
        .unwrap_or_else(|| format!("0x{:x}", ip))
}

// ── Linux ────────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod linux {
    use super::{StackFrame, StackTrace, resolve};
    use nix::sys::ptrace;
    use nix::sys::wait::{WaitStatus, waitpid};
    use nix::unistd::Pid;

    pub fn capture(pid: u32, regions: &[crate::types::Region]) -> Result<StackTrace, String> {
        let nix_pid = Pid::from_raw(pid as i32);

        ptrace::attach(nix_pid).map_err(|e| format!("ptrace attach: {e}"))?;
        match waitpid(nix_pid, None).map_err(|e| format!("waitpid: {e}"))? {
            WaitStatus::Stopped(_, _) => {}
            s => return Err(format!("unexpected stop status: {s:?}")),
        }

        let regs = ptrace::getregs(nix_pid).map_err(|e| format!("getregs: {e}"))?;
        let frames = unwind(
            nix_pid,
            regs.rip as usize,
            regs.rsp as usize,
            regs.rbp as usize,
            regions,
        );

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

        let region = regions
            .iter()
            .find(|r| ip >= r.base && ip < r.base + r.size);
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
        let elf_load_base: u64 = obj
            .segments()
            .filter_map(|s| {
                use object::ObjectSegment;
                if s.file_range().0 == 0 {
                    Some(s.address())
                } else {
                    None
                }
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

        let load =
            |id: gimli::SectionId| -> gimli::Result<gimli::EndianSlice<gimli::RunTimeEndian>> {
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
            if rbp == 0 || rbp < rsp {
                break;
            }

            let return_address = peek(pid, rbp + 8).unwrap_or(0);
            let symbol = resolve_sym(rip, regions);

            frames.push(StackFrame {
                instruction_pointer: rip,
                base_pointer: rbp,
                return_address,
                symbol,
            });

            if return_address == 0 {
                break;
            }
            let prev_rbp = peek(pid, rbp).unwrap_or(0);
            rip = return_address;
            rsp = rbp + 16;
            rbp = prev_rbp;
        }
        frames
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use super::{StackFrame, StackTrace};
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::Debug::AddrModeFlat;
    use windows::Win32::System::Diagnostics::Debug::{
        CONTEXT, STACKFRAME64, SYMBOL_INFO, StackWalk64, SymCleanup, SymFromAddr, SymInitialize,
    };
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows::Win32::System::SystemInformation::IMAGE_FILE_MACHINE_AMD64;
    use windows::Win32::System::Threading::{
        OpenProcess, OpenThread, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, ResumeThread,
        SuspendThread, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION, THREAD_SUSPEND_RESUME,
    };

    pub fn capture(pid: u32, regions: &[crate::types::Region]) -> Result<StackTrace, String> {
        unsafe {
            // open process
            let proc_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
                .map_err(|e| format!("OpenProcess failed: {:?}", e))?;

            // initialize DbgHelp symbols
            SymInitialize(proc_handle, None, true)
                .map_err(|e| format!("SymInitialize failed: {:?}", e))?;

            // get all thread IDs for this process
            let thread_ids = get_thread_ids(pid);
            if thread_ids.is_empty() {
                let _ = SymCleanup(proc_handle);
                CloseHandle(proc_handle).ok();
                return Err("no threads found".to_string());
            }

            let mut all_frames = Vec::new();

            // walk stack for each thread
            for tid in &thread_ids {
                let thread_handle = match OpenThread(
                    THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME,
                    false,
                    *tid,
                ) {
                    Ok(h) => h,
                    Err(_) => continue,
                };

                // suspend thread so registers are stable
                SuspendThread(thread_handle);
                use std::alloc::{Layout, alloc_zeroed};

                // allocate 16-byte aligned CONTEXT
                let layout = Layout::from_size_align(std::mem::size_of::<CONTEXT>(), 16).unwrap();
                let ctx_ptr = alloc_zeroed(layout) as *mut CONTEXT;
                let ctx = &mut *ctx_ptr;

                ctx.ContextFlags =
                    windows::Win32::System::Diagnostics::Debug::CONTEXT_FLAGS(0x100007); // CONTEXT_FULL

                if windows::Win32::System::Diagnostics::Debug::GetThreadContext(thread_handle, ctx)
                    .is_ok()
                {
                    // set up initial stack frame
                    let mut sf = STACKFRAME64::default();
                    sf.AddrPC.Offset = ctx.Rip;
                    sf.AddrPC.Mode = AddrModeFlat;
                    sf.AddrFrame.Offset = ctx.Rbp;
                    sf.AddrFrame.Mode = AddrModeFlat;
                    sf.AddrStack.Offset = ctx.Rsp;
                    sf.AddrStack.Mode = AddrModeFlat;
                    // walk up to 64 frames
                    for _ in 0..64 {
                        let ok = StackWalk64(
                            IMAGE_FILE_MACHINE_AMD64.0 as u32,
                            proc_handle,
                            thread_handle,
                            &mut sf,
                            ctx as *mut _ as *mut _,
                            None,
                            None,
                            None,
                            None,
                        );
                        if !ok.as_bool() {
                            break;
                        }

                        let ip = sf.AddrPC.Offset as usize;
                        if ip == 0 {
                            break;
                        }

                        // resolve symbol name
                        let sym_size = std::mem::size_of::<SYMBOL_INFO>() + 256;
                        let mut sym_buf = vec![0u8; sym_size];
                        let sym = sym_buf.as_mut_ptr() as *mut SYMBOL_INFO;
                        (*sym).SizeOfStruct = std::mem::size_of::<SYMBOL_INFO>() as u32;
                        (*sym).MaxNameLen = 255;

                        let symbol = if SymFromAddr(proc_handle, ip as u64, None, sym).is_ok() {
                            let name_len = (*sym).NameLen as usize;
                            let name_ptr = (*sym).Name.as_ptr() as *const u8;
                            let slice = std::slice::from_raw_parts(name_ptr, name_len);
                            String::from_utf8_lossy(slice).to_string()
                        } else {
                            // fall back to region-based resolution
                            super::resolve(ip, regions)
                        };

                        all_frames.push(StackFrame {
                            instruction_pointer: ip,
                            base_pointer: sf.AddrFrame.Offset as usize,
                            return_address: sf.AddrReturn.Offset as usize,
                            symbol,
                        });
                    }
                }

                std::alloc::dealloc(ctx_ptr as *mut u8, layout);

                ResumeThread(thread_handle);
                CloseHandle(thread_handle).ok();
            }

            let _ = SymCleanup(proc_handle);
            CloseHandle(proc_handle).ok();

            Ok(StackTrace {
                pid,
                frames: all_frames,
            })
        }
    }

    fn get_thread_ids(pid: u32) -> Vec<u32> {
        let mut threads = Vec::new();
        unsafe {
            let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
                Ok(h) => h,
                Err(_) => return threads,
            };

            let mut entry = THREADENTRY32::default();
            entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

            if Thread32First(snapshot, &mut entry).is_ok() {
                loop {
                    if entry.th32OwnerProcessID == pid {
                        threads.push(entry.th32ThreadID);
                    }
                    if Thread32Next(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }
        }
        threads
    }
}
