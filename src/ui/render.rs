use crate::types::Region;
use crate::types::RegionKind::*;
use crate::types::RegionProtect::*;
use crate::types::RegionState::*;
use crate::utils::formatting::format_bytes;

/// Prints a color-coded ASCII memory map bar to stdout scaled to `width` characters.
pub fn render_bar(regions: &[Region], labels: &[&str], width: usize) {
    let total: usize = regions.iter().map(|r| r.size).sum();
    let mut bar = String::new();

    for (i, mbi) in regions.iter().enumerate() {
        let chars = ((mbi.size as f64 / total as f64) * width as f64).max(1.0) as usize;

        let symbol = match labels[i] {
            "stack-live" => format!("\x1b[36m{}\x1b[0m", "S".repeat(chars)),
            "stack-guard" => format!("\x1b[31m{}\x1b[0m", "G".repeat(chars)),
            "stack-reserved" => format!("\x1b[90m{}\x1b[0m", "r".repeat(chars)),
            "heap" => format!("\x1b[35m{}\x1b[0m", "H".repeat(chars)),
            "image" => format!("\x1b[34m{}\x1b[0m", "I".repeat(chars)),
            _ if mbi.state == Free => format!("\x1b[90m{}\x1b[0m", ".".repeat(chars)),
            _ if mbi.kind == Image => format!("\x1b[34m{}\x1b[0m", "I".repeat(chars)),
            _ if mbi.kind == Mapped => format!("\x1b[32m{}\x1b[0m", "M".repeat(chars)),
            _ if mbi.protect == Execute => format!("\x1b[33m{}\x1b[0m", "X".repeat(chars)),
            _ if mbi.state == Reserved => format!("\x1b[90m{}\x1b[0m", "r".repeat(chars)),
            _ => format!("\x1b[90m{}\x1b[0m", "?".repeat(chars)),
        };

        bar.push_str(&symbol);
    }

    println!("{}", bar);
}

use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};

/// Returns a ratatui [`Line`] of colored spans representing the memory map, scaled to `width` characters.
pub fn render_bar_tui(regions: &[Region], labels: &[&str], width: usize) -> Line<'static> {
    let total: usize = regions.iter().map(|r| r.size).sum();
    let mut spans: Vec<Span> = vec![];

    for (i, mbi) in regions.iter().enumerate() {
        let chars = ((mbi.size as f64 / total as f64) * width as f64).max(1.0) as usize;

        let (symbol, color) = match labels[i] {
            "stack-live" => ("S", Color::Cyan),
            "stack-guard" => ("G", Color::Red),
            "stack-reserved" => ("r", Color::DarkGray),
            "heap" => ("H", Color::Magenta),
            "image" => ("I", Color::Blue),
            _ if mbi.state == Free => (".", Color::DarkGray),
            _ if mbi.kind == Image => ("I", Color::Blue),
            _ if mbi.kind == Mapped => ("M", Color::Green),
            _ if mbi.protect == Execute => ("X", Color::Yellow),
            _ if mbi.state == Reserved => ("r", Color::DarkGray),
            _ => ("?", Color::DarkGray),
        };

        spans.push(Span::styled(
            symbol.repeat(chars),
            Style::default().fg(color),
        ));
    }

    Line::from(spans)
}

/// Prints a tabular listing of memory regions with address, size, label, and name to stdout.
///
/// Regions labeled `"?"` are skipped.
pub fn render_verbose(regions: &[Region], labels: &[&str]) {
    for (i, region) in regions.iter().enumerate() {
        if labels[i] == "?" {
            continue;
        }

        let name = if region.name.is_empty() {
            labels[i].to_string()
        } else {
            region.name.clone()
        };

        println!(
            "{:<18} {:<12} {:<16} {}",
            format!("0x{:x}", region.base),
            format_bytes(region.size as u64),
            labels[i],
            name,
        );
    }
}

/// Returns a [`Vec`] of ratatui [`Line`]s with a tabular listing of memory regions.
///
/// Regions labeled `"?"` are skipped.
pub fn render_verbose_tui(regions: &[Region], labels: &[&str]) -> Vec<Line<'static>> {
    let mut output: Vec<Line> = vec![];
    for (i, region) in regions.iter().enumerate() {
        if labels[i] == "?" {
            continue;
        }

        let name = if region.name.is_empty() {
            labels[i].to_string()
        } else {
            region.name.clone()
        };

        output.push(Line::raw(format!(
            "{:<18} {:<12} {:<16} {}",
            format!("0x{:x}", region.base),
            format_bytes(region.size as u64),
            labels[i],
            name,
        )));
    }
    output
}
