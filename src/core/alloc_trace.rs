#[cfg(target_os = "windows")]
    mod windows{
    /// Experimental Allocation Tracing
    /// Still in Development
    /// -SickleFire
    use windows::Win32::Foundation::DBG_CONTINUE;
    use windows::Win32::System::Diagnostics::Debug::{
        ContinueDebugEvent, DEBUG_EVENT, DebugActiveProcess, DebugActiveProcessStop,
        EXIT_PROCESS_DEBUG_EVENT, WaitForDebugEvent,
    };
    
    pub fn trace_allocations(pid: u32, duration_secs: u64) {
        unsafe {
            DebugActiveProcess(pid).expect("failed to attach");
            println!("attached to pid {}", pid);
        
            let mut event = DEBUG_EVENT::default();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(duration_secs);
        
            loop {
                if std::time::Instant::now() > deadline {
                    break;
                }
            
                WaitForDebugEvent(&mut event, 100);
            
                match event.dwDebugEventCode {
                    EXIT_PROCESS_DEBUG_EVENT => {
                        println!("process exited");
                        break;
                    }
                    code => {
                        println!("debug event: {}", code.0);
                    }
                }
            
                ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE);
            }
        
            DebugActiveProcessStop(pid).ok();
            println!("detached");
        }
    }
}
