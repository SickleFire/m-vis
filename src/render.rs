use windows::Win32::System::Memory::{
    MEMORY_BASIC_INFORMATION, MEM_FREE, MEM_RESERVE,
    MEM_IMAGE, MEM_MAPPED,
    PAGE_EXECUTE, PAGE_EXECUTE_READ,
};

pub fn render_bar(regions: &[MEMORY_BASIC_INFORMATION], width: usize) {
    let total: usize = regions.iter().map(|r| r.RegionSize).sum();
    let mut bar = String::new();

    for mbi in regions {
        // how many chars does this region get?
        let chars = ((mbi.RegionSize as f64 / total as f64) * width as f64).max(1.0) as usize;

        let symbol = if mbi.State == MEM_FREE {
            format!("\x1b[90m{}\x1b[0m", ".".repeat(chars))   // gray  = free
        } else if mbi.Type == MEM_IMAGE {
            format!("\x1b[34m{}\x1b[0m", "I".repeat(chars))   // blue  = image (.exe/.dll)
        } else if mbi.Type == MEM_MAPPED {
            format!("\x1b[32m{}\x1b[0m", "M".repeat(chars))   // green = mapped
        } else if mbi.Protect.contains(PAGE_EXECUTE_READ)
               || mbi.Protect.contains(PAGE_EXECUTE) {
            format!("\x1b[33m{}\x1b[0m", "X".repeat(chars))   // amber = executable
        } else if mbi.State == MEM_RESERVE {
            format!("\x1b[90m{}\x1b[0m", "r".repeat(chars))   // gray  = reserved
        } else {
            format!("\x1b[35m{}\x1b[0m", "P".repeat(chars))   // purple= private heap/stack
        };

        bar.push_str(&symbol);
    }

    println!("{}", bar);
}