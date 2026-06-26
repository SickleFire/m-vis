// src/utils/formatting.rs

const KB: f64 = 1024.0;
const MB: f64 = KB * 1024.0;
const GB: f64 = MB * 1024.0;
const TB: f64 = GB * 1024.0;

pub fn format_bytes(size: u64) -> String {
    let size_f = size as f64;

    if size_f >= TB {
        format!("{:.2} TB", size_f / TB)
    } else if size_f >= GB {
        format!("{:.2} GB", size_f / GB)
    } else if size_f >= MB {
        format!("{:.2} MB", size_f / MB)
    } else if size_f >= KB {
        format!("{:.2} KB", size_f / KB)
    } else {
        format!("{} B", size)
    }
}

pub fn format_bytes_i64(size: i64) -> String {
    let abs_size = size.abs() as f64;

    let formatted = if abs_size >= TB {
        format!("{:.2} TB", abs_size / TB)
    } else if abs_size >= GB {
        format!("{:.2} GB", abs_size / GB)
    } else if abs_size >= MB {
        format!("{:.2} MB", abs_size / MB)
    } else if abs_size >= KB {
        format!("{:.2} KB", abs_size / KB)
    } else {
        format!("{} B", abs_size as u64)
    };

    if size < 0 {
        format!("-{}", formatted)
    } else {
        formatted
    }
}
