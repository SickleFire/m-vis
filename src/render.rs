use crate::types::Region;
use crate::types::RegionKind::*;
use crate::types::RegionProtect::*;
use crate::types::RegionState::*;

pub fn render_bar(regions: &[Region], labels: &[&str], width: usize) {
    let total: usize = regions.iter().map(|r| r.size).sum();
    let mut bar = String::new();

    for (i, mbi) in regions.iter().enumerate() {
        let chars = ((mbi.size as f64 / total as f64) * width as f64).max(1.0) as usize;

        let symbol = match labels[i] {
            "stack-live"     => format!("\x1b[36m{}\x1b[0m", "S".repeat(chars)),
            "stack-guard"    => format!("\x1b[31m{}\x1b[0m", "G".repeat(chars)),
            "stack-reserved" => format!("\x1b[90m{}\x1b[0m", "r".repeat(chars)),
            "heap"           => format!("\x1b[35m{}\x1b[0m", "H".repeat(chars)),
            _ if mbi.state == Free                               => format!("\x1b[90m{}\x1b[0m", ".".repeat(chars)),
            _ if mbi.kind == Image                             => format!("\x1b[34m{}\x1b[0m", "I".repeat(chars)),
            _ if mbi.kind  == Mapped                            => format!("\x1b[32m{}\x1b[0m", "M".repeat(chars)),
            _ if mbi.protect == Execute                  => format!("\x1b[33m{}\x1b[0m", "X".repeat(chars)),
            _ if mbi.state == Reserved                             => format!("\x1b[90m{}\x1b[0m", "r".repeat(chars)),
            _                                                         => format!("\x1b[90m{}\x1b[0m", "?".repeat(chars)),
        };

        bar.push_str(&symbol);
    }

    println!("{}", bar);
}

pub fn render_verbose(regions: &[Region], labels: &[&str]) {
    for (i, region) in regions.iter().enumerate() {
        if labels[i] == "?" { continue; }

        let name = if region.name.is_empty() {
            labels[i].to_string()
        } else {
            region.name.clone()
        };

        println!("{:<18} {:<12} {:<16} {}",
            format!("0x{:x}", region.base),
            format_size(region.size),
            labels[i],
            name,
        );
    }
}

fn format_size(bytes: usize) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.1}MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else {
        format!("{}B", bytes)
    }
}