use windows::Win32::System::Memory::{
    MEMORY_BASIC_INFORMATION, MEM_FREE, MEM_RESERVE,
    MEM_IMAGE, MEM_MAPPED,
    PAGE_EXECUTE, PAGE_EXECUTE_READ,
};

pub fn render_bar(regions: &[MEMORY_BASIC_INFORMATION], labels: &[&str], width: usize) {
    let total: usize = regions.iter().map(|r| r.RegionSize).sum();
    let mut bar = String::new();

    for (i, mbi) in regions.iter().enumerate() {
        let chars = ((mbi.RegionSize as f64 / total as f64) * width as f64).max(1.0) as usize;

        let symbol = match labels[i] {
            "stack-live"     => format!("\x1b[36m{}\x1b[0m", "S".repeat(chars)),
            "stack-guard"    => format!("\x1b[31m{}\x1b[0m", "G".repeat(chars)),
            "stack-reserved" => format!("\x1b[90m{}\x1b[0m", "r".repeat(chars)),
            "heap"           => format!("\x1b[35m{}\x1b[0m", "H".repeat(chars)),
            _ if mbi.State == MEM_FREE                                => format!("\x1b[90m{}\x1b[0m", ".".repeat(chars)),
            _ if mbi.Type  == MEM_IMAGE                               => format!("\x1b[34m{}\x1b[0m", "I".repeat(chars)),
            _ if mbi.Type  == MEM_MAPPED                              => format!("\x1b[32m{}\x1b[0m", "M".repeat(chars)),
            _ if mbi.Protect.contains(PAGE_EXECUTE_READ)
              || mbi.Protect.contains(PAGE_EXECUTE)                   => format!("\x1b[33m{}\x1b[0m", "X".repeat(chars)),
            _ if mbi.State == MEM_RESERVE                             => format!("\x1b[90m{}\x1b[0m", "r".repeat(chars)),
            _                                                         => format!("\x1b[90m{}\x1b[0m", "?".repeat(chars)),
        };

        bar.push_str(&symbol);
    }

    println!("{}", bar);
}