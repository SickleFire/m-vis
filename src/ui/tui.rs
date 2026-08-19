use color_eyre::Result;
use crossterm::event::{self, KeyCode, KeyEventKind};
use ratatui::layout::{Constraint, Layout, Position};
use ratatui::style::{Modifier, Style, Stylize};
use ratatui::text::Span;
use ratatui::text::{Line, Text};
use ratatui::widgets::{Axis, Chart, Dataset, Wrap};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::{DefaultTerminal, Frame};

use super::commands;
use crate::core::delta::{DiagnosticSeverity, LeakDelta};
use crate::core::hex_dump::format_hex_dump;
use crate::os::{MemoryProvider, provider};
use crate::types::{HeapBlock, RegionProtect};
use crate::ui::commands::ScanResult;
use crate::ui::theme::{Theme, ThemeKind};
use crate::utils::formatting::{format_bytes, format_bytes_i64};
use crate::utils::loader::load_heap_snapshot;
use crate::utils::process::{TreeDisplayRow, build_process_tree, flatten_tree};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

const SIZE_BUCKETS: [(&str, usize, usize); 6] = [
    ("0-64B", 0, 64),
    ("65-512B", 64, 512),
    ("513B-4KB", 512, 4 * 1024),
    ("4-64KB", 4 * 1024, 64 * 1024),
    ("64KB-1MB", 64 * 1024, 1024 * 1024),
    (">1MB", 1024 * 1024, usize::MAX),
];

const HEAP_VIEW_ORDER: [HeapViewMode; 6] = [
    HeapViewMode::Metrics,
    HeapViewMode::Allocations,
    HeapViewMode::Chart,
    HeapViewMode::Histogram,
    HeapViewMode::PointerTree,
    HeapViewMode::HexDump,
];
const SETTINGS_ROW_COUNT: usize = 12;

fn heap_view_index(mode: HeapViewMode) -> usize {
    HEAP_VIEW_ORDER.iter().position(|&m| m == mode).unwrap_or(0)
}

fn heap_view_label(mode: HeapViewMode) -> &'static str {
    match mode {
        HeapViewMode::Metrics => "Metrics",
        HeapViewMode::Allocations => "Allocations",
        HeapViewMode::Chart => "Chart",
        HeapViewMode::Histogram => "Histogram",
        HeapViewMode::PointerTree => "Ptr Tree",
        HeapViewMode::HexDump => "Hex Inspector",
    }
}

fn read_memory_bytes(pid: u32, address: usize, size: usize) -> Result<Vec<u8>, String> {
    let mem = provider();
    mem.read_process_memory(pid, address, size)
}

#[derive(Default)]
struct Settings {
    watch_interval_millis: u64,
    theme_kind: ThemeKind,
    badge_caution_mb_s: f64,
    badge_warning_mb_s: f64,
    badge_critical_mb_s: f64,
    enabled_views: [bool; 6], // indexed via heap_view_index
    default_view_idx: usize,
}

impl Settings {
    fn new(theme_kind: ThemeKind) -> Self {
        Self {
            watch_interval_millis: 50,
            theme_kind,
            badge_caution_mb_s: 2.0,
            badge_warning_mb_s: 20.0,
            badge_critical_mb_s: 100.0,
            enabled_views: [true; 6],
            default_view_idx: 0,
        }
    }

    fn is_enabled(&self, mode: HeapViewMode) -> bool {
        self.enabled_views[heap_view_index(mode)]
    }

    fn default_view(&self) -> HeapViewMode {
        HEAP_VIEW_ORDER[self.default_view_idx]
    }

    /// Next enabled view after `current`, wrapping; falls back to `current`
    /// if somehow nothing else is enabled.
    fn next_enabled_view(&self, current: HeapViewMode) -> HeapViewMode {
        let start = heap_view_index(current);
        for step in 1..=HEAP_VIEW_ORDER.len() {
            let idx = (start + step) % HEAP_VIEW_ORDER.len();
            if self.enabled_views[idx] {
                return HEAP_VIEW_ORDER[idx];
            }
        }
        current
    }
}

enum AppEvent {
    DiffResult(Vec<HeapBlock>, ScanResult),
    BaseLine(ScanResult),
    ScanResult(ScanResult),
    ScanError(String),
    Output(Line<'static>),
    RunCommand(String),
    LeakResult(LeakDelta),
}

/// Initializes the terminal and runs the interactive TUI application until the user quits.
pub fn tui_main(theme_kind: ThemeKind) -> Result<()> {
    color_eyre::install()?;
    let terminal = ratatui::init(); // replaces ratatui::run
    let result = App::new(theme_kind).run(terminal);
    ratatui::restore();
    result
}

struct HeapSnapshot {
    fragmentation: f64,
    used_blocks: usize,
    free_blocks: usize,
    used_bytes: usize,
    free_bytes: usize,
    largest_free: usize,
    largest_used: usize,
    blocks: Vec<HeapBlock>, // store raw blocks for the table
    pointer_blocks: std::collections::HashSet<usize>,
    pub referenced_blocks: std::collections::HashSet<usize>,
    pub pointer_edges: std::collections::HashMap<usize, Vec<crate::types::PointerEdge>>,
}

struct PointerTreeRow {
    address: usize,
    size: usize,
    depth: usize,
    has_children: bool,
    is_collapsed: bool,
    is_leaf: bool,
    is_dangling: bool,
    is_cycle: bool,
    is_shared: bool,
}

fn flatten_pointer_tree(
    root: usize,
    edges: &std::collections::HashMap<usize, Vec<crate::types::PointerEdge>>,
    sizes: &std::collections::HashMap<usize, usize>,
    collapsed: &std::collections::HashSet<usize>,
    rows: &mut Vec<PointerTreeRow>,
) {
    const MAX_ROWS: usize = 5_000; // safety cap regardless of graph shape

    fn walk(
        addr: usize,
        depth: usize,
        path: &mut Vec<usize>,
        visited: &mut std::collections::HashSet<usize>, // NEW: global, not just ancestor path
        edges: &std::collections::HashMap<usize, Vec<crate::types::PointerEdge>>,
        sizes: &std::collections::HashMap<usize, usize>,
        collapsed: &std::collections::HashSet<usize>,
        rows: &mut Vec<PointerTreeRow>,
    ) {
        if rows.len() >= MAX_ROWS {
            return;
        }

        let is_cycle = path.contains(&addr);
        // Only count this as "shared" (not a true cycle) if it's not on the
        // current ancestor path. First visit anywhere inserts and continues;
        // any later visit from a different branch is a dup, not a loop.
        let is_shared = !is_cycle && !visited.insert(addr);

        let size = sizes.get(&addr).copied().unwrap_or(0);
        let children: &[crate::types::PointerEdge] = if is_cycle || is_shared {
            &[]
        } else {
            edges.get(&addr).map(|v| v.as_slice()).unwrap_or(&[])
        };
        let has_children = !children.is_empty();

        rows.push(PointerTreeRow {
            address: addr,
            size,
            depth,
            has_children,
            is_collapsed: collapsed.contains(&addr),
            is_leaf: !has_children,
            is_dangling: false,
            is_cycle,
            is_shared,
        });

        if is_cycle || is_shared || collapsed.contains(&addr) || depth >= MAX_POINTER_TREE_DEPTH {
            return;
        }

        path.push(addr);
        for edge in children {
            if rows.len() >= MAX_ROWS {
                break;
            }
            if edge.target_is_free {
                rows.push(PointerTreeRow {
                    address: edge.target,
                    size: sizes.get(&edge.target).copied().unwrap_or(0),
                    depth: depth + 1,
                    has_children: false,
                    is_collapsed: false,
                    is_leaf: true,
                    is_dangling: true,
                    is_cycle: false,
                    is_shared: false,
                });
            } else {
                walk(
                    edge.target,
                    depth + 1,
                    path,
                    visited,
                    edges,
                    sizes,
                    collapsed,
                    rows,
                );
            }
        }
        path.pop();
    }

    let mut path = Vec::new();
    let mut visited = std::collections::HashSet::new();
    walk(
        root,
        0,
        &mut path,
        &mut visited,
        edges,
        sizes,
        collapsed,
        rows,
    );

    if rows.len() >= MAX_ROWS {
        rows.push(PointerTreeRow {
            address: 0,
            size: 0,
            depth: 0,
            has_children: false,
            is_collapsed: false,
            is_leaf: true,
            is_dangling: false,
            is_cycle: false,
            is_shared: false,
        });
    }
}

#[derive(Default)]
struct ViewState {
    pub selected: usize,
    pub scroll: usize,
}

impl ViewState {
    fn next(&mut self, max: usize, wrap: bool) {
        if max == 0 {
            return;
        }
        if wrap {
            self.selected = (self.selected + 1) % max;
        } else if self.selected + 1 < max {
            self.selected += 1;
        }
    }

    fn prev(&mut self, max: usize, wrap: bool) {
        if max == 0 {
            return;
        }
        if wrap {
            self.selected = (self.selected + max - 1) % max;
        } else {
            self.selected = self.selected.saturating_sub(1);
        }
    }
}

#[derive(Default)]
struct ProcListView {
    pub items: Vec<String>,
    pub state: ViewState,
}

#[derive(Default)]
struct AllocTreeView {
    pub rows: Vec<TreeDisplayRow>,
    pub collapsed: std::collections::HashSet<u32>,
    pub total_memory: u64,
    pub state: ViewState,
}

#[derive(Default)]
struct PointerTreeView {
    pub root: Option<usize>,
    pub rows: Vec<PointerTreeRow>,
    pub collapsed: std::collections::HashSet<usize>,
    pub state: ViewState,
}

#[derive(Default)]
struct HistogramView {
    pub state: ViewState,
}

#[derive(Default)]
struct HexDumpView {
    pub address: Option<usize>,
    pub bytes: Vec<u8>,
    pub scroll: usize,
}

#[derive(Default)]
struct SettingsView {
    pub open: bool,
    pub settings: Settings,
    pub state: ViewState,
}

fn spawn_job<F>(tx: std::sync::mpsc::Sender<AppEvent>, job: F)
where
    F: FnOnce(std::sync::mpsc::Sender<AppEvent>) -> Result<(), String> + Send + 'static,
{
    std::thread::spawn(move || {
        if let Err(e) = job(tx.clone()) {
            tx.send(AppEvent::Output(Line::raw(format!("error: {}", e))))
                .ok();
        }
    });
}

/// App holds the state of the application
struct App {
    proc_list: ProcListView,
    alloc_tree: AllocTreeView,
    pointer_tree: PointerTreeView,
    histogram: HistogramView,
    hex_dump: HexDumpView,
    settings_view: SettingsView,

    /// Current value of the input box
    input: String,
    /// Position of cursor in the editor area.
    character_index: usize,
    /// Current input mode
    input_mode: InputMode,
    /// History of recorded messages
    messages: Vec<Line<'static>>,
    scroll_offset: u16,
    messages_height: u16,
    current_proc: Option<String>,
    current_pid: Option<u32>,
    current_memory_mb: Option<u64>,
    heap_history: Vec<HeapSnapshot>,
    current_baseline: Option<ScanResult>,
    alloc_table_page: usize,      // current page
    alloc_table_page_size: usize, // rows per page, derived from panel height
    alloc_table_selected: usize,  // highlighted row
    heap_view_mode: HeapViewMode,
    tx: std::sync::mpsc::Sender<AppEvent>,
    rx: std::sync::mpsc::Receiver<AppEvent>,
    is_loading: bool,
    loading_msg: String,
    watch_stop: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    busy: std::sync::Arc<AtomicBool>,
    leak_deltas: Vec<LeakDelta>,
    theme: Theme,
    focus: Focus,
    prompt: Option<PromptState>,
    watch_target: Option<String>,
    watch_mode: Option<String>,
    swap_panels: bool,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum HeapViewMode {
    Metrics,     // high-level view
    Allocations, // table view
    Chart,       // Chart
    Histogram,   // allocation size distribution
    PointerTree,
    HexDump, // raw memory inspector (hex + ASCII)
}

const MAX_POINTER_TREE_DEPTH: usize = 16;
enum InputMode {
    Normal,
    Editing,
}

#[derive(PartialEq, Debug)]
enum Focus {
    ProcList,
    Tree,
    AllocTable,
}

struct PromptField {
    label: &'static str,
    value: String,
}

enum PromptKind {
    Leak,  // secs
    LeakM, // secs, samples
    Watch, // mode: -h/-m/-l
}

struct PromptState {
    kind: PromptKind,
    proc_name: String,
    fields: Vec<PromptField>,
    selected: usize,
}

//macro_rules! run_command {
//    ($self:expr, $command:expr) => {
//        $self.handle_command($command);
//    };
//}

impl App {
    fn new(theme_kind: ThemeKind) -> Self {
        let (tx, rx) = std::sync::mpsc::channel();
        let theme = theme_kind.theme();
        let settings = Settings::new(theme_kind);
        let _default_view = settings.default_view();
        let mut app = Self {
            input: String::new(),
            input_mode: InputMode::Normal,
            messages: Vec::new(),
            character_index: 0,
            scroll_offset: 0,
            messages_height: 0,
            current_proc: None,
            current_pid: None,
            current_memory_mb: None,
            heap_history: vec![],
            current_baseline: None,
            alloc_table_page: 0,
            alloc_table_page_size: 0,
            alloc_table_selected: 0,
            heap_view_mode: HeapViewMode::Metrics,
            tx,
            rx,
            is_loading: false,
            loading_msg: String::new(),
            watch_stop: None,
            busy: std::sync::Arc::new(AtomicBool::new(false)),
            leak_deltas: vec![],
            theme,
            proc_list: ProcListView::default(),
            alloc_tree: AllocTreeView::default(),
            pointer_tree: PointerTreeView::default(),
            histogram: HistogramView::default(),
            hex_dump: HexDumpView::default(),
            settings_view: SettingsView {
                settings,
                ..Default::default()
            },
            focus: Focus::AllocTable,
            prompt: None,
            watch_target: None,
            watch_mode: None,
            swap_panels: false,
        };
        app.push_message("mvis ready. type 'help' for commands.".into());
        app
    }

    fn open_prompt(&mut self, kind: PromptKind) {
        if let Some(name) = self.selected_proc_name() {
            let fields = match kind {
                PromptKind::Leak => vec![PromptField {
                    label: "secs",
                    value: String::new(),
                }],
                PromptKind::LeakM => vec![
                    PromptField {
                        label: "secs",
                        value: String::new(),
                    },
                    PromptField {
                        label: "samples",
                        value: String::new(),
                    },
                ],
                PromptKind::Watch => vec![PromptField {
                    label: "mode (-h/-m/-l)",
                    value: "-l".into(),
                }],
            };
            self.prompt = Some(PromptState {
                kind,
                proc_name: name,
                fields,
                selected: 0,
            });
        }
    }

    fn prompt_confirm(&mut self) {
        if let Some(p) = self.prompt.take() {
            let cmd = match p.kind {
                PromptKind::Leak => format!("leak {} {}", p.proc_name, p.fields[0].value),
                PromptKind::LeakM => format!(
                    "leak-m {} {} {}",
                    p.proc_name, p.fields[0].value, p.fields[1].value
                ),
                PromptKind::Watch => format!("watch {} {}", p.proc_name, p.fields[0].value),
            };
            self.dispatch(&cmd);
        }
    }

    fn prompt_cancel(&mut self) {
        self.prompt = None;
    }

    fn prompt_next_field(&mut self) {
        if let Some(p) = &mut self.prompt {
            p.selected = (p.selected + 1) % p.fields.len();
        }
    }

    fn prompt_prev_field(&mut self) {
        if let Some(p) = &mut self.prompt {
            p.selected = (p.selected + p.fields.len() - 1) % p.fields.len();
        }
    }

    fn prompt_push_char(&mut self, c: char) {
        if let Some(p) = &mut self.prompt {
            p.fields[p.selected].value.push(c);
        }
    }

    fn prompt_backspace(&mut self) {
        if let Some(p) = &mut self.prompt {
            p.fields[p.selected].value.pop();
        }
    }

    fn scroll_up(&mut self) {
        self.scroll_offset = self.scroll_offset.saturating_sub(1);
    }

    fn scroll_down(&mut self) {
        self.scroll_offset = self.scroll_offset.saturating_add(1);
    }

    fn push_message(&mut self, msg: String) {
        self.messages.push(Line::raw(msg)); // wrap in Line
        let len = self.messages.len() as u16;
        if len > self.messages_height {
            self.scroll_offset = len - self.messages_height;
        }
    }

    fn push_line(&mut self, line: Line<'static>) {
        self.messages.push(line);
        let len = self.messages.len() as u16;
        if len > self.messages_height {
            self.scroll_offset = len - self.messages_height;
        }
    }

    fn clear_output(&mut self) {
        self.messages.clear();
        self.scroll_offset = 0;
    }

    /// Compute a memory-growth alert badge from the latest leak deltas.
    /// Returns (label, style) for the badge, or None if no leak data is available.
    fn compute_badge(&self) -> Option<(String, Style)> {
        let count = self.leak_deltas.len();
        if count < 2 {
            return None;
        }
        // Use the last delta's net change as the current per-sample growth.
        // Watch mode samples every ~2 seconds, so this approximates MB/s.
        let last = self.leak_deltas.last().unwrap();
        let net = last.net_change();
        if net <= 0 {
            return Some((
                "✓ HEALTHY".into(),
                Style::default()
                    .fg(self.theme.healthy)
                    .add_modifier(Modifier::BOLD),
            ));
        }
        let net_mb = net as f64 / (1024.0 * 1024.0);
        // Average per-sample MB rate (spanning count-1 intervals of ~2s each)
        let per_sample_rate = net_mb;
        if per_sample_rate > self.settings_view.settings.badge_critical_mb_s {
            Some((
                "◆ CRITICAL".into(),
                Style::default()
                    .fg(self.theme.growth_critical)
                    .add_modifier(Modifier::BOLD | Modifier::RAPID_BLINK),
            ))
        } else if per_sample_rate > self.settings_view.settings.badge_warning_mb_s {
            Some((
                "▲ WARNING".into(),
                Style::default()
                    .fg(self.theme.growth_critical)
                    .add_modifier(Modifier::BOLD),
            ))
        } else if per_sample_rate > self.settings_view.settings.badge_caution_mb_s {
            Some((
                "△ CAUTION".into(),
                Style::default()
                    .fg(self.theme.growth_warning)
                    .add_modifier(Modifier::BOLD),
            ))
        } else {
            Some((
                "✓ HEALTHY".into(),
                Style::default()
                    .fg(self.theme.healthy)
                    .add_modifier(Modifier::BOLD),
            ))
        }
    }

    fn move_cursor_left(&mut self) {
        let cursor_moved_left = self.character_index.saturating_sub(1);
        self.character_index = self.clamp_cursor(cursor_moved_left);
    }

    fn move_cursor_right(&mut self) {
        let cursor_moved_right = self.character_index.saturating_add(1);
        self.character_index = self.clamp_cursor(cursor_moved_right);
    }

    fn enter_char(&mut self, new_char: char) {
        let index = self.byte_index();
        self.input.insert(index, new_char);
        self.move_cursor_right();
    }

    /// Returns the byte index based on the character position.
    ///
    /// Since each character in a string can contain multiple bytes, it's necessary to calculate
    /// the byte index based on the index of the character.
    fn byte_index(&self) -> usize {
        self.input
            .char_indices()
            .map(|(i, _)| i)
            .nth(self.character_index)
            .unwrap_or(self.input.len())
    }

    fn delete_char(&mut self) {
        let is_not_cursor_leftmost = self.character_index != 0;
        if is_not_cursor_leftmost {
            // Method "remove" is not used on the saved text for deleting the selected char.
            // Reason: Using remove on String works on bytes instead of the chars.
            // Using remove would require special care because of char boundaries.

            let current_index = self.character_index;
            let from_left_to_current_index = current_index - 1;

            // Getting all characters before the selected character.
            let before_char_to_delete = self.input.chars().take(from_left_to_current_index);
            // Getting all characters after selected character.
            let after_char_to_delete = self.input.chars().skip(current_index);

            // Put all characters together except the selected one.
            // By leaving the selected one out, it is forgotten and therefore deleted.
            self.input = before_char_to_delete.chain(after_char_to_delete).collect();
            self.move_cursor_left();
        }
    }

    fn clamp_cursor(&self, new_cursor_pos: usize) -> usize {
        new_cursor_pos.clamp(0, self.input.chars().count())
    }

    fn reset_cursor(&mut self) {
        self.character_index = 0;
    }
    fn next_page(&mut self) {
        if let Some(snap) = self.heap_history.last() {
            let used_blocks: Vec<_> = snap.blocks.iter().filter(|b| !b.is_free).collect();
            let max_page = used_blocks.len() / self.alloc_table_page_size;
            if self.alloc_table_page < max_page {
                self.alloc_table_page += 1;
                self.alloc_table_selected = 0;
            }
        }
    }

    fn prev_page(&mut self) {
        if self.alloc_table_page > 0 {
            self.alloc_table_page -= 1;
            self.alloc_table_selected = 0;
        }
    }

    fn select_next_row(&mut self) {
        if self.alloc_table_selected + 1 < self.alloc_table_page_size {
            self.alloc_table_selected += 1;
        }
    }

    fn select_prev_row(&mut self) {
        self.alloc_table_selected = self.alloc_table_selected.saturating_sub(1);
    }

    fn refresh_proc_list(&mut self) {
        let args = vec![""];
        match commands::list_processes(args) {
            Ok(procs) => {
                self.proc_list.items = procs;
                if self.proc_list.state.selected >= self.proc_list.items.len() {
                    self.proc_list.state.selected = self.proc_list.items.len().saturating_sub(1);
                }
                self.proc_list.state.scroll = self
                    .proc_list
                    .state
                    .scroll
                    .min(self.proc_list.state.selected);
            }
            Err(e) => self.push_message(format!("Error: {e}")),
        }
    }

    fn selected_proc_name(&self) -> Option<String> {
        self.proc_list
            .items
            .get(self.proc_list.state.selected)
            .and_then(|row| row.split_whitespace().nth(1))
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    }

    fn set_focus(&mut self, target: Focus) {
        // pressing the same key twice returns focus to the alloc table
        self.focus = if self.focus == target {
            Focus::AllocTable
        } else {
            target
        };
        match self.focus {
            Focus::Tree => self.refresh_tree(),
            Focus::ProcList => self.refresh_proc_list(),
            Focus::AllocTable => {}
        }
    }

    fn refresh_tree(&mut self) {
        if let Some(pid) = self.current_pid
            && let Some(tree) = build_process_tree(pid)
        {
            self.alloc_tree.total_memory = tree.total_memory();
            let mut rows = Vec::new();
            flatten_tree(&tree, 0, &self.alloc_tree.collapsed, &mut rows);
            self.alloc_tree.rows = rows;
            if self.alloc_tree.state.selected >= self.alloc_tree.rows.len() {
                self.alloc_tree.state.selected = self.alloc_tree.rows.len().saturating_sub(1);
            }
            self.alloc_tree.state.scroll = self
                .alloc_tree
                .state
                .scroll
                .min(self.alloc_tree.state.selected);
        }
    }

    fn tree_toggle_collapse(&mut self) {
        if let Some(row) = self.alloc_tree.rows.get(self.alloc_tree.state.selected)
            && row.has_children
        {
            let pid = row.pid;
            if self.alloc_tree.collapsed.contains(&pid) {
                self.alloc_tree.collapsed.remove(&pid);
            } else {
                self.alloc_tree.collapsed.insert(pid);
            }
            self.refresh_tree();
        }
    }

    fn insert_at_cursor(&mut self, text: &str) {
        let index = self.byte_index();
        self.input.insert_str(index, text);
        self.character_index += text.chars().count();
    }

    fn submit_message(&mut self) {
        let raw = self.input.trim().to_string();
        self.input.clear();
        self.reset_cursor();
        if raw.is_empty() {
            return;
        }
        self.dispatch(&raw);
    }

    fn dispatch(&mut self, cmd: &str) {
        let raw = cmd.trim().to_string();
        if raw.is_empty() {
            return;
        }

        self.push_message(format!("> {raw}"));

        let parts: Vec<&str> = raw.split_whitespace().collect();
        self.handle_command(parts);
    }

    fn compute_watch_badge(&self) -> Option<(String, Style)> {
        let target = self.watch_target.as_ref()?;
        let mode = self.watch_mode.as_deref().unwrap_or("");
        Some((
            format!("● watching {} ({})", target, mode),
            Style::default()
                .fg(self.theme.growth_warning)
                .add_modifier(Modifier::BOLD),
        ))
    }

    /// Jump the Allocations table to the page containing the first (largest)
    /// block that falls in the currently selected histogram bucket, then
    /// switch views to show it.
    fn jump_to_histogram_bucket(&mut self) {
        let Some(snap) = self.heap_history.last() else {
            return;
        };
        let (_, lo, hi) = SIZE_BUCKETS[self.histogram.state.selected];

        let mut used_blocks: Vec<_> = snap.blocks.iter().filter(|b| !b.is_free).collect();
        used_blocks.sort_by(|a, b| b.size.cmp(&a.size)); // same order as render_alloc_table

        if let Some(idx) = used_blocks.iter().position(|b| b.size > lo && b.size <= hi)
            && self.alloc_table_page_size > 0
        {
            self.alloc_table_page = idx / self.alloc_table_page_size;
            self.alloc_table_selected = idx % self.alloc_table_page_size;
            self.heap_view_mode = HeapViewMode::Allocations;
        }
    }

    fn settings_adjust(&mut self, dir: i32) {
        match self.settings_view.state.selected {
            0 => {
                let v = self.settings_view.settings.watch_interval_millis as i64 + dir as i64;
                self.settings_view.settings.watch_interval_millis = v.max(1) as u64;
            }
            1 => {
                self.settings_view.settings.theme_kind = if dir > 0 {
                    self.settings_view.settings.theme_kind.next()
                } else {
                    self.settings_view.settings.theme_kind.prev()
                };
                self.theme = self.settings_view.settings.theme_kind.theme();
            }
            2 => {
                self.settings_view.settings.badge_caution_mb_s =
                    (self.settings_view.settings.badge_caution_mb_s + dir as f64).max(0.1)
            }
            3 => {
                self.settings_view.settings.badge_warning_mb_s =
                    (self.settings_view.settings.badge_warning_mb_s + dir as f64).max(0.1)
            }
            4 => {
                self.settings_view.settings.badge_critical_mb_s =
                    (self.settings_view.settings.badge_critical_mb_s + dir as f64).max(0.1)
            }
            5..=10 => self.settings_toggle_view(self.settings_view.state.selected - 5),
            11 => {
                let len = HEAP_VIEW_ORDER.len();
                let mut idx = self.settings_view.settings.default_view_idx;
                for _ in 0..len {
                    idx = ((idx as i64 + dir as i64).rem_euclid(len as i64)) as usize;
                    if self.settings_view.settings.enabled_views[idx] {
                        self.settings_view.settings.default_view_idx = idx;
                        break;
                    }
                }
            }
            _ => {}
        }
    }

    fn settings_activate(&mut self) {
        if (5..=10).contains(&self.settings_view.state.selected) {
            self.settings_toggle_view(self.settings_view.state.selected - 5);
        } else {
            self.settings_adjust(1);
        }
    }

    fn settings_toggle_view(&mut self, idx: usize) {
        let enabled_count = self
            .settings_view
            .settings
            .enabled_views
            .iter()
            .filter(|&&e| e)
            .count();
        if self.settings_view.settings.enabled_views[idx] && enabled_count <= 1 {
            return; // never allow disabling the last remaining view
        }
        self.settings_view.settings.enabled_views[idx] =
            !self.settings_view.settings.enabled_views[idx];

        if !self.settings_view.settings.enabled_views[self.settings_view.settings.default_view_idx]
            && let Some(next) =
                (0..HEAP_VIEW_ORDER.len()).find(|&i| self.settings_view.settings.enabled_views[i])
        {
            self.settings_view.settings.default_view_idx = next;
        }
        if !self.settings_view.settings.is_enabled(self.heap_view_mode) {
            self.heap_view_mode = self
                .settings_view
                .settings
                .next_enabled_view(self.heap_view_mode);
        }
    }

    fn enter_pointer_tree(&mut self, addr: usize) {
        self.pointer_tree.root = Some(addr);
        self.pointer_tree.state.selected = 0;
        self.pointer_tree.state.scroll = 0;
        self.pointer_tree.collapsed.clear();
        self.heap_view_mode = HeapViewMode::PointerTree;
        self.refresh_pointer_tree();
    }

    fn refresh_pointer_tree(&mut self) {
        let Some(root) = self.pointer_tree.root else {
            return;
        };
        let rows = {
            let Some(snap) = self.heap_history.last() else {
                return;
            };
            let sizes: std::collections::HashMap<usize, usize> =
                snap.blocks.iter().map(|b| (b.address, b.size)).collect();
            let mut rows = Vec::new();
            flatten_pointer_tree(
                root,
                &snap.pointer_edges,
                &sizes,
                &self.pointer_tree.collapsed,
                &mut rows,
            );
            rows
        };
        self.pointer_tree.rows = rows;
        if self.pointer_tree.state.selected >= self.pointer_tree.rows.len() {
            self.pointer_tree.state.selected = self.pointer_tree.rows.len().saturating_sub(1);
        }
        self.pointer_tree.state.scroll = self
            .pointer_tree
            .state
            .scroll
            .min(self.pointer_tree.state.selected);
    }

    fn pointer_tree_toggle_collapse(&mut self) {
        let target = self
            .pointer_tree
            .rows
            .get(self.pointer_tree.state.selected)
            .filter(|row| row.has_children)
            .map(|row| row.address);
        if let Some(addr) = target {
            if self.pointer_tree.collapsed.contains(&addr) {
                self.pointer_tree.collapsed.remove(&addr);
            } else {
                self.pointer_tree.collapsed.insert(addr);
            }
            self.refresh_pointer_tree();
        }
    }

    fn inspect_selected_block(&mut self) {
        let (pid, addr, size) = {
            let Some(pid) = self.current_pid else {
                self.push_message("no process selected to inspect memory".into());
                return;
            };
            let Some(snap) = self.heap_history.last() else {
                self.push_message("no heap snapshot available".into());
                return;
            };
            let mut used_blocks: Vec<_> = snap.blocks.iter().filter(|b| !b.is_free).collect();
            used_blocks.sort_by(|a, b| b.size.cmp(&a.size));
            let idx =
                self.alloc_table_page * self.alloc_table_page_size + self.alloc_table_selected;
            let Some(block) = used_blocks.get(idx) else {
                return;
            };
            (pid, block.address, block.size.min(512).max(64))
        };

        match read_memory_bytes(pid, addr, size) {
            Ok(bytes) => {
                self.hex_dump.address = Some(addr);
                self.hex_dump.bytes = bytes;
                self.hex_dump.scroll = 0;
                self.heap_view_mode = HeapViewMode::HexDump;
                self.push_message(format!(
                    "inspecting memory at 0x{:x} ({} bytes)",
                    addr, size
                ));
            }
            Err(e) => {
                self.push_message(format!("failed to read memory: {e}"));
            }
        }
    }

    /// Jumps into the pointer tree rooted at the currently selected Allocations
    /// row, if that block has any pointer relationships.
    fn try_enter_pointer_tree(&mut self) {
        let addr_and_flag = {
            let Some(snap) = self.heap_history.last() else {
                return;
            };
            let mut used_blocks: Vec<_> = snap.blocks.iter().filter(|b| !b.is_free).collect();
            used_blocks.sort_by(|a, b| b.size.cmp(&a.size)); // same order as render_alloc_table
            let idx =
                self.alloc_table_page * self.alloc_table_page_size + self.alloc_table_selected;
            used_blocks.get(idx).map(|block| {
                let addr = block.address;
                let has_ptr_info =
                    snap.pointer_blocks.contains(&addr) || snap.referenced_blocks.contains(&addr);
                (addr, has_ptr_info)
            })
        };

        match addr_and_flag {
            Some((addr, true)) => self.enter_pointer_tree(addr),
            Some((_, false)) => {
                self.push_message("selected block has no pointer relationships".into())
            }
            None => {}
        }
    }

    fn handle_command(&mut self, parts: Vec<&str>) {
        match parts.clone().as_slice() {
            ["baseline", _proc] => {
                let proc = _proc.to_string();
                spawn_job(self.tx.clone(), move |tx| {
                    let result = commands::scan(vec!["scan", &proc, "-h"])?;
                    tx.send(AppEvent::BaseLine(result)).ok();
                    tx.send(AppEvent::Output(Line::raw("Baseline set".to_string())))
                        .ok();
                    Ok(())
                });
            }
            ["diff", _proc] => {
                if self.current_baseline.is_none() {
                    self.push_message("no baseline set — run 'baseline <proc>' first".into());
                    return;
                }

                let baseline_blocks = self.current_baseline.as_ref().unwrap().blocks.clone();
                let proc_name = _proc.to_string();

                spawn_job(self.tx.clone(), move |tx| {
                    let result = commands::scan(vec!["scan", &proc_name, "-h"])?;
                    tx.send(AppEvent::DiffResult(baseline_blocks, result)).ok();
                    Ok(())
                });
            }
            ["diff", file_a, file_b] => {
                let path_a = file_a.to_string();
                let path_b = file_b.to_string();

                spawn_job(self.tx.clone(), move |tx| {
                    let a =
                        load_heap_snapshot(&path_a).map_err(|e| format!("{}: {}", path_a, e))?;
                    let b =
                        load_heap_snapshot(&path_b).map_err(|e| format!("{}: {}", path_b, e))?;
                    tx.send(AppEvent::DiffResult(a.blocks, b)).ok();
                    Ok(())
                });
            }
            ["save", _proc, _file] => {
                let proc = _proc.to_string();
                let path = _file.to_string();

                self.push_message(format!("scanning {} to save as {}...", proc, path));

                spawn_job(self.tx.clone(), move |tx| {
                    let result = commands::scan(vec!["scan", &proc, "-h"])?;
                    let json = serde_json::to_string_pretty(&result)
                        .map_err(|e| format!("failed to serialize snapshot: {}", e))?;
                    std::fs::write(&path, json)
                        .map_err(|e| format!("failed to write {}: {}", path, e))?;
                    tx.send(AppEvent::Output(Line::raw(format!(
                        "saved snapshot to {}",
                        path
                    ))))
                    .ok();
                    Ok(())
                });
            }
            ["clearbaseline"] => {
                self.current_baseline = None;
            }
            ["watch", _proc, _mode] => {
                let proc = _proc.to_string();
                let mode = _mode.to_string();
                let tx = self.tx.clone();
                let busy = self.busy.clone();

                let interval = self.settings_view.settings.watch_interval_millis.max(100);

                // build the command string to dispatch
                let cmd = match mode.as_str() {
                    "-h" => format!("scan {} -h", proc),
                    "-m" => format!("modules {}", proc),
                    "-l" => format!("leak {} 1", proc),
                    _ => {
                        self.push_message("unknown watch mode".into());
                        return;
                    }
                };
                // stop any existing watch
                if let Some(stop) = &self.watch_stop {
                    stop.store(true, std::sync::atomic::Ordering::Relaxed);
                }

                let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                self.watch_stop = Some(stop.clone());
                self.watch_target = Some(proc.clone());
                self.watch_mode = Some(mode.clone());

                self.push_message(format!("watching: {}", cmd));

                std::thread::spawn(move || {
                    let mut i = 0u64;
                    loop {
                        if stop.load(std::sync::atomic::Ordering::Relaxed) {
                            tx.send(AppEvent::Output(Line::raw(format!(
                                "watch stopped at iteration {}",
                                i
                            ))))
                            .ok();
                            break;
                        }

                        busy.store(true, Ordering::Relaxed);
                        tx.send(AppEvent::RunCommand(cmd.clone())).ok();

                        let mut waited_ms = 0u64;
                        while busy.load(Ordering::Relaxed) {
                            if stop.load(Ordering::Relaxed) {
                                break;
                            }
                            std::thread::sleep(std::time::Duration::from_millis(interval));
                            waited_ms += 50;

                            // safety timeout — don't hang forever if something never completes
                            if waited_ms > 30_000 {
                                tx.send(AppEvent::Output(Line::raw(
                                    "watch: command timed out, continuing anyway".to_string(),
                                )))
                                .ok();
                                break;
                            }
                        }

                        if stop.load(Ordering::Relaxed) {
                            tx.send(AppEvent::Output(Line::raw(format!(
                                "watch stopped at iteration {}",
                                i
                            ))))
                            .ok();
                            break;
                        }

                        std::thread::sleep(std::time::Duration::from_secs(1));
                        i += 1;
                    }
                    tx.send(AppEvent::Output("watch complete".into())).ok();
                });
            }
            ["stopwatch"] => {
                if let Some(stop) = &self.watch_stop {
                    stop.store(true, std::sync::atomic::Ordering::Relaxed);
                    self.push_message("stopping watch...".into());
                } else {
                    self.push_message("no watch running".into());
                }
                self.watch_target = None;
                self.watch_mode = None;
            }
            ["leak-m", _proc, _secs, _samples] => {
                let proc_name = _proc.to_string();
                let secs = _secs.to_string();
                let samples = _samples.to_string();

                self.push_message(format!("starting leak-m for {}...", proc_name));

                spawn_job(self.tx.clone(), move |tx| {
                    let (line_tx, line_rx) = std::sync::mpsc::channel::<Line<'static>>();
                    let tx2 = tx.clone();

                    std::thread::spawn(move || {
                        let args = vec![
                            "leak-m",
                            proc_name.as_str(),
                            secs.as_str(),
                            samples.as_str(),
                        ];
                        if let Err(e) = commands::leak_m(args, line_tx) {
                            tx2.send(AppEvent::Output(Line::from(Span::styled(
                                format!("error: {}", e),
                                Style::default().fg(crate::ui::theme::ThemeKind::default()
                                    .theme()
                                    .growth_critical),
                            ))))
                            .ok();
                        }
                    });

                    while let Ok(line) = line_rx.recv() {
                        tx.send(AppEvent::Output(line)).ok();
                    }
                    Ok(())
                });
            }
            ["leak", _proc, _secs] => {
                let proc_name = _proc.to_string();
                let parts_owned: Vec<String> = parts.iter().map(|s| s.to_string()).collect();
                self.is_loading = true;
                self.loading_msg = format!("scanning leak for {}...", proc_name);

                spawn_job(self.tx.clone(), move |tx| {
                    let parts_ref: Vec<&str> = parts_owned.iter().map(|s| s.as_str()).collect();
                    match commands::leak(parts_ref) {
                        Ok(result) => {
                            for line in result.0 {
                                tx.send(AppEvent::Output(line)).ok();
                            }
                            tx.send(AppEvent::LeakResult(result.1)).ok();
                        }
                        Err(e) => {
                            tx.send(AppEvent::Output(Line::raw(e.to_string()))).ok();
                        }
                    };
                    Ok(())
                });
            }
            ["scan", _proc, "-h"] | ["scan", _proc, "-h", "-g"] => {
                let proc_name = _proc.to_string();
                let parts_owned: Vec<String> = parts.iter().map(|s| s.to_string()).collect();
                self.is_loading = true;
                self.loading_msg = format!("scanning heap for {}...", proc_name);
                self.push_message(self.loading_msg.clone());

                spawn_job(self.tx.clone(), move |tx| {
                    let parts_ref: Vec<&str> = parts_owned.iter().map(|s| s.as_str()).collect();
                    match commands::scan(parts_ref) {
                        Ok(result) => tx.send(AppEvent::ScanResult(result)).ok(),
                        Err(e) => tx.send(AppEvent::ScanError(e)).ok(),
                    };
                    Ok(())
                });
            }
            ["scan", _proc, "-a"] | ["scan", _proc, "-v"] => {
                let parts_owned: Vec<String> = parts.iter().map(|s| s.to_string()).collect();
                self.push_message(format!("scanning {}...", _proc));

                spawn_job(self.tx.clone(), move |tx| {
                    let parts_ref: Vec<&str> = parts_owned.iter().map(|s| s.as_str()).collect();
                    match commands::scan(parts_ref) {
                        Ok(result) => tx.send(AppEvent::ScanResult(result)).ok(),
                        Err(e) => tx.send(AppEvent::ScanError(e)).ok(),
                    };
                    Ok(())
                });
            }
            ["list"] => match commands::list_processes(parts) {
                Ok(procs) => {
                    for p in procs {
                        self.push_message(p);
                    }
                }
                Err(e) => self.push_message(format!("Error: {e}")),
            },
            ["modules", _proc, "-t"] | ["modules", _proc] => match commands::modules(parts) {
                Ok(results) => {
                    for result in results {
                        self.push_message(result);
                    }
                }
                Err(e) => self.push_message(format!("Error: {e}")),
            },
            ["dump", _proc, _addr] | ["dump", _proc, _addr, _] => {
                let proc_input = _proc.to_string();
                let addr_input = _addr.to_string();
                let len_input = parts.get(3).copied().unwrap_or("128").to_string();

                let pid = if let Ok(p) = proc_input.parse::<u32>() {
                    Some(p)
                } else if let Some(p) = self
                    .current_pid
                    .filter(|_| self.current_proc.as_deref() == Some(&proc_input))
                {
                    Some(p)
                } else {
                    self.proc_list.items.iter().find_map(|line| {
                        let tokens: Vec<&str> = line.split_whitespace().collect();
                        if tokens.get(1) == Some(&proc_input.as_str())
                            || tokens.iter().any(|&t| t == proc_input)
                        {
                            tokens.first().and_then(|s| s.parse::<u32>().ok())
                        } else {
                            None
                        }
                    })
                };

                let Some(pid) = pid else {
                    self.push_message(format!("Process '{}' not found or invalid PID", proc_input));
                    return;
                };

                let addr = if let Some(hex) = addr_input
                    .strip_prefix("0x")
                    .or_else(|| addr_input.strip_prefix("0X"))
                {
                    usize::from_str_radix(hex, 16)
                } else {
                    usize::from_str_radix(&addr_input, 16).or_else(|_| addr_input.parse::<usize>())
                };

                let Ok(addr) = addr else {
                    self.push_message(format!("Invalid address format: {}", addr_input));
                    return;
                };

                let len = len_input
                    .strip_prefix("0x")
                    .or_else(|| len_input.strip_prefix("0X"))
                    .and_then(|s| usize::from_str_radix(s, 16).ok())
                    .or_else(|| len_input.parse::<usize>().ok())
                    .unwrap_or(128);

                match read_memory_bytes(pid, addr, len) {
                    Ok(bytes) => {
                        self.push_line(Line::from(Span::styled(
                            format!(
                                "─ Memory Dump: 0x{:x} ({} bytes) PID {} ─",
                                addr,
                                bytes.len(),
                                pid
                            ),
                            Style::default()
                                .fg(self.theme.cyan)
                                .add_modifier(Modifier::BOLD),
                        )));
                        let dump_lines = format_hex_dump(addr, &bytes);
                        for l in &dump_lines {
                            self.push_line(Line::raw(l.clone()));
                        }
                        self.push_line(Line::raw("─".repeat(50)));

                        self.hex_dump.address = Some(addr);
                        self.hex_dump.bytes = bytes;
                        self.hex_dump.scroll = 0;
                        self.heap_view_mode = HeapViewMode::HexDump;
                    }
                    Err(e) => {
                        self.push_message(format!("Error dumping memory: {e}"));
                    }
                }
            }
            ["clear"] => self.clear_output(),
            ["help"] => {
                self.push_message("commands:".into());
                self.push_message("  scan   <proc> -a          memory map".into());
                self.push_message("  scan   <proc> -h          heap stats".into());
                self.push_message("  scan   <proc> -v          loaded dlls".into());
                self.push_message("  dump   <proc/pid> <addr> [len] dump raw memory bytes".into());
                self.push_message("  leak   <proc> secs        detect leaks".into());
                self.push_message("  leak-m <proc> secs samp   detect leaks-samples".into());
                self.push_message(
                    "  watch  <proc> -flag       watch processes indefinitely".into(),
                );
                self.push_message(
                    "  stopwatch                 stop the current watch process".into(),
                );
                self.push_message("  baseline <proc>".into());
                self.push_message("  diff     <proc>".into());
                self.push_message("  clearbaseline".into());
                self.push_message("  list                      list processes".into());
                self.push_message("  clear                     clear output history".into());
                self.push_message("  [t key]                   toggle process tree view".into());
                self.push_message("  [S key]                   open settings panel".into());
                self.push_message(
                    "  [x key]                   swap output/heap view panels".into(),
                );
            }
            _ => {
                self.push_message(format!("unknown command: {}", parts.join(" ")));
                self.push_message("type 'help' for available commands".into());
            }
        }
    }

    fn run(mut self, mut terminal: DefaultTerminal) -> Result<()> {
        loop {
            // check for background results
            while let Ok(event) = self.rx.try_recv() {
                match event {
                    AppEvent::DiffResult(baseline_blocks, current) => {
                        use std::collections::HashSet;

                        let baseline_addrs: HashSet<usize> = baseline_blocks
                            .iter()
                            .filter(|b| !b.is_free)
                            .map(|b| b.address)
                            .collect();

                        let current_addrs: HashSet<usize> = current
                            .blocks
                            .iter()
                            .filter(|b| !b.is_free)
                            .map(|b| b.address)
                            .collect();

                        // new blocks — in current but not baseline
                        let new_blocks: Vec<_> = current
                            .blocks
                            .iter()
                            .filter(|b| !b.is_free && !baseline_addrs.contains(&b.address))
                            .collect();

                        // removed blocks — in baseline but not current
                        let removed_blocks: Vec<_> = baseline_blocks
                            .iter()
                            .filter(|b| !b.is_free && !current_addrs.contains(&b.address))
                            .collect();

                        let new_bytes: usize = new_blocks.iter().map(|b| b.size).sum();
                        let removed_bytes: usize = removed_blocks.iter().map(|b| b.size).sum();
                        let net: i64 = new_bytes as i64 - removed_bytes as i64;

                        let baseline_total: usize = baseline_blocks
                            .iter()
                            .filter(|b| !b.is_free)
                            .map(|b| b.size)
                            .sum();
                        let current_total: usize = current
                            .blocks
                            .iter()
                            .filter(|b| !b.is_free)
                            .map(|b| b.size)
                            .sum();

                        // header
                        self.push_line(Line::raw("─".repeat(40)));
                        self.push_line(Line::raw(format!(
                            "baseline : {} blocks ({})",
                            baseline_blocks.iter().filter(|b| !b.is_free).count(),
                            format_bytes(baseline_total as u64),
                        )));
                        self.push_line(Line::raw(format!(
                            "current  : {} blocks ({})",
                            current.blocks.iter().filter(|b| !b.is_free).count(),
                            format_bytes(current_total as u64),
                        )));
                        self.push_line(Line::raw("─".repeat(40)));

                        // new blocks
                        self.push_line(Line::from(Span::styled(
                            format!(
                                "+{} new blocks (+{})",
                                new_blocks.len(),
                                format_bytes(new_bytes as u64),
                            ),
                            Style::default().fg(self.theme.healthy),
                        )));
                        for block in new_blocks.iter().take(5) {
                            self.push_line(Line::from(Span::styled(
                                format!(
                                    "  + 0x{:x}  {}",
                                    block.address,
                                    format_bytes(block.size as u64)
                                ),
                                Style::default().fg(self.theme.healthy),
                            )));
                        }
                        if new_blocks.len() > 5 {
                            self.push_line(Line::raw(format!(
                                "  ... and {} more",
                                new_blocks.len() - 5
                            )));
                        }

                        // removed blocks
                        self.push_line(Line::from(Span::styled(
                            format!(
                                "-{} removed (-{})",
                                removed_blocks.len(),
                                format_bytes(removed_bytes as u64)
                            ),
                            Style::default().fg(self.theme.growth_critical),
                        )));

                        // net growth
                        let net_color = if net > 0 {
                            self.theme.growth_critical
                        } else {
                            self.theme.healthy
                        };
                        let net_sign = if net > 0 { "+" } else { "" };
                        self.push_line(Line::from(Span::styled(
                            format!("net growth: {}{}", net_sign, format_bytes_i64(net)),
                            Style::default().fg(net_color),
                        )));

                        // verdict
                        let verdict = if net > 1024 * 1024 {
                            (
                                "LEAK CONFIRMED — significant growth",
                                self.theme.growth_critical,
                            )
                        } else if net > 0 {
                            (
                                "growth detected — monitor over time",
                                self.theme.growth_warning,
                            )
                        } else {
                            ("no growth — heap stable", self.theme.healthy)
                        };
                        self.push_line(Line::from(Span::styled(
                            verdict.0,
                            Style::default().fg(verdict.1),
                        )));
                        self.push_line(Line::raw("─".repeat(40)));

                        // update heap history with current
                        let used: Vec<_> = current.blocks.iter().filter(|b| !b.is_free).collect();
                        let free: Vec<_> = current.blocks.iter().filter(|b| b.is_free).collect();
                        self.heap_history.push(HeapSnapshot {
                            fragmentation: current.frag,
                            used_blocks: used.len(),
                            free_blocks: free.len(),
                            used_bytes: current.used_bytes,
                            free_bytes: current.free_bytes,
                            largest_used: used.iter().map(|b| b.size).max().unwrap_or(0),
                            largest_free: free.iter().map(|b| b.size).max().unwrap_or(0),
                            blocks: current.blocks,
                            pointer_blocks: current.pointer_blocks,
                            referenced_blocks: current.referenced_blocks,
                            pointer_edges: current.pointer_edges,
                        });
                        if self.heap_history.len() > 4 {
                            self.heap_history.remove(0);
                        }
                    }
                    AppEvent::BaseLine(result) => {
                        self.current_baseline = Some(result);
                    }
                    AppEvent::ScanResult(result) => {
                        //Updates Heap View doesnt Differentiate between -h, -a or -v
                        self.is_loading = false;
                        self.busy.store(false, Ordering::Relaxed);
                        self.current_proc = Some(result.pid.to_string());
                        self.current_pid = Some(result.pid);
                        self.current_memory_mb = Some(result.memory_mb);

                        for line in result.lines {
                            self.push_line(line);
                        }

                        let used: Vec<_> = result.blocks.iter().filter(|b| !b.is_free).collect();
                        let free: Vec<_> = result.blocks.iter().filter(|b| b.is_free).collect();

                        self.heap_history.push(HeapSnapshot {
                            fragmentation: result.frag,
                            used_blocks: used.len(),
                            free_blocks: free.len(),
                            used_bytes: result.used_bytes,
                            free_bytes: result.free_bytes,
                            largest_used: used.iter().map(|b| b.size).max().unwrap_or(0),
                            largest_free: free.iter().map(|b| b.size).max().unwrap_or(0),
                            blocks: result.blocks,
                            pointer_blocks: result.pointer_blocks,
                            referenced_blocks: result.referenced_blocks,
                            pointer_edges: result.pointer_edges,
                        });

                        if self.heap_history.len() > 4 {
                            self.heap_history.remove(0);
                        }
                    }
                    AppEvent::ScanError(e) => {
                        self.is_loading = false;
                        self.busy.store(false, Ordering::Relaxed);
                        self.push_message(format!("error: {}", e));
                    }
                    AppEvent::Output(line) => {
                        self.push_line(line);
                    }
                    AppEvent::RunCommand(command) => {
                        self.dispatch(&command);
                        if !self.is_loading {
                            self.busy.store(false, Ordering::Relaxed);
                        }
                    }
                    AppEvent::LeakResult(delta) => {
                        self.is_loading = false;
                        self.busy.store(false, Ordering::Relaxed);
                        self.leak_deltas.push(delta);
                        if self.leak_deltas.len() > 30 {
                            self.leak_deltas.remove(0);
                        }
                    }
                }
            }

            terminal.draw(|frame| self.render(frame))?;

            if self.prompt.is_some() {
                if let Some(key) = event::read()?.as_key_press_event() {
                    match key.code {
                        KeyCode::Esc => self.prompt_cancel(),
                        KeyCode::Enter => self.prompt_confirm(),
                        KeyCode::Tab => self.prompt_next_field(),
                        KeyCode::BackTab => self.prompt_prev_field(),
                        KeyCode::Char(c) => self.prompt_push_char(c),
                        KeyCode::Backspace => self.prompt_backspace(),
                        _ => {}
                    }
                }
                continue; // skip normal-mode key handling this iteration
            }

            if self.settings_view.open {
                if let Some(key) = event::read()?.as_key_press_event() {
                    match key.code {
                        KeyCode::Esc | KeyCode::Char('S') => self.settings_view.open = false,
                        KeyCode::Char('j') | KeyCode::Down => {
                            self.settings_view.state.next(SETTINGS_ROW_COUNT, true)
                        }
                        KeyCode::Char('k') | KeyCode::Up => {
                            self.settings_view.state.prev(SETTINGS_ROW_COUNT, true)
                        }
                        KeyCode::Char('h') | KeyCode::Left => self.settings_adjust(-1),
                        KeyCode::Char('l') | KeyCode::Right => self.settings_adjust(1),
                        KeyCode::Enter => self.settings_activate(),
                        _ => {}
                    }
                }
                continue;
            }

            if crossterm::event::poll(std::time::Duration::from_millis(100))?
                && let Some(key) = event::read()?.as_key_press_event()
            {
                match self.input_mode {
                    InputMode::Normal => match key.code {
                        KeyCode::Char('e') => self.input_mode = InputMode::Editing,
                        KeyCode::Char('q') => return Ok(()),
                        KeyCode::Char('t') => self.set_focus(Focus::Tree),
                        KeyCode::Char('S') => self.settings_view.open = !self.settings_view.open,
                        KeyCode::Char('x') => self.swap_panels = !self.swap_panels,
                        KeyCode::Up => self.scroll_up(),
                        KeyCode::Down => self.scroll_down(),
                        KeyCode::Tab => {
                            self.heap_view_mode = self
                                .settings_view
                                .settings
                                .next_enabled_view(self.heap_view_mode);
                        }
                        KeyCode::Char('p') => self.set_focus(Focus::ProcList),
                        KeyCode::Char('r') if self.focus == Focus::ProcList => {
                            self.refresh_proc_list()
                        }
                        KeyCode::Char(']') => self.next_page(),
                        KeyCode::Char('[') => self.prev_page(),
                        KeyCode::Char('j') => match self.focus {
                            Focus::Tree => self
                                .alloc_tree
                                .state
                                .next(self.alloc_tree.rows.len(), false),
                            Focus::ProcList => {
                                self.proc_list.state.next(self.proc_list.items.len(), false)
                            }
                            Focus::AllocTable => match self.heap_view_mode {
                                HeapViewMode::Histogram => {
                                    self.histogram.state.next(SIZE_BUCKETS.len(), false)
                                }
                                HeapViewMode::PointerTree => self
                                    .pointer_tree
                                    .state
                                    .next(self.pointer_tree.rows.len(), false),
                                HeapViewMode::HexDump => {
                                    self.hex_dump.scroll = self.hex_dump.scroll.saturating_add(1);
                                }
                                _ => self.select_next_row(),
                            },
                        },
                        KeyCode::Char('k') => match self.focus {
                            Focus::Tree => self
                                .alloc_tree
                                .state
                                .prev(self.alloc_tree.rows.len(), false),
                            Focus::ProcList => {
                                self.proc_list.state.prev(self.proc_list.items.len(), false)
                            }
                            Focus::AllocTable => match self.heap_view_mode {
                                HeapViewMode::Histogram => {
                                    self.histogram.state.prev(SIZE_BUCKETS.len(), false)
                                }
                                HeapViewMode::PointerTree => self
                                    .pointer_tree
                                    .state
                                    .prev(self.pointer_tree.rows.len(), false),
                                HeapViewMode::HexDump => {
                                    self.hex_dump.scroll = self.hex_dump.scroll.saturating_sub(1);
                                }
                                _ => self.select_prev_row(),
                            },
                        },
                        KeyCode::Enter => match self.focus {
                            Focus::Tree => self.tree_toggle_collapse(),
                            Focus::ProcList => {
                                if let Some(name) = self.selected_proc_name() {
                                    self.dispatch(&format!("scan {} -h", name));
                                }
                            }
                            Focus::AllocTable => match self.heap_view_mode {
                                HeapViewMode::Histogram => self.jump_to_histogram_bucket(),
                                HeapViewMode::Allocations => self.try_enter_pointer_tree(),
                                HeapViewMode::PointerTree => self.pointer_tree_toggle_collapse(),
                                _ => {}
                            },
                        },
                        KeyCode::Esc
                            if self.heap_view_mode == HeapViewMode::PointerTree
                                || self.heap_view_mode == HeapViewMode::HexDump =>
                        {
                            self.heap_view_mode = HeapViewMode::Allocations;
                        }
                        KeyCode::Char('a') if self.focus == Focus::ProcList => {
                            if let Some(name) = self.selected_proc_name() {
                                self.dispatch(&format!("scan {} -a", name));
                            }
                        }
                        KeyCode::Char('v') if self.focus == Focus::ProcList => {
                            if let Some(name) = self.selected_proc_name() {
                                self.dispatch(&format!("scan {} -v", name));
                            }
                        }
                        KeyCode::Char('b') if self.focus == Focus::ProcList => {
                            if let Some(name) = self.selected_proc_name() {
                                self.dispatch(&format!("baseline {}", name));
                            }
                        }
                        KeyCode::Char('d') => match self.focus {
                            Focus::ProcList => {
                                if let Some(name) = self.selected_proc_name() {
                                    self.dispatch(&format!("diff {}", name));
                                }
                            }
                            Focus::AllocTable => {
                                self.inspect_selected_block();
                            }
                            _ => {}
                        },
                        KeyCode::Char('i') if self.focus == Focus::ProcList => {
                            if let Some(name) = self.selected_proc_name() {
                                self.insert_at_cursor(&format!("{} ", name));
                                self.input_mode = InputMode::Editing;
                            }
                        }
                        KeyCode::Char('l') if self.focus == Focus::ProcList => {
                            self.open_prompt(PromptKind::Leak)
                        }
                        KeyCode::Char('L') if self.focus == Focus::ProcList => {
                            self.open_prompt(PromptKind::LeakM)
                        }
                        KeyCode::Char('w') if self.focus == Focus::ProcList => {
                            self.open_prompt(PromptKind::Watch)
                        }

                        _ => {}
                    },
                    InputMode::Editing if key.kind == KeyEventKind::Press => match key.code {
                        KeyCode::Enter => self.submit_message(),
                        KeyCode::Char(to_insert) => self.enter_char(to_insert),
                        KeyCode::Backspace => self.delete_char(),
                        KeyCode::Left => self.move_cursor_left(),
                        KeyCode::Right => self.move_cursor_right(),
                        KeyCode::Up => self.scroll_up(),
                        KeyCode::Down => self.scroll_down(),
                        KeyCode::Esc => self.input_mode = InputMode::Normal,
                        _ => {}
                    },
                    InputMode::Editing => {}
                }
            }
        }
    }

    fn render(&mut self, frame: &mut Frame) {
        frame.render_widget(
            ratatui::widgets::Paragraph::new("")
                .style(Style::default().bg(self.theme.bg).fg(self.theme.text)),
            frame.area(),
        );
        let hexdump_active = self.heap_view_mode == HeapViewMode::HexDump;
        let (left_pct, right_pct) = match (hexdump_active, self.swap_panels) {
            (true, true) => (60, 40),
            (true, false) => (40, 60),
            (false, _) => (50, 50),
        };
        let outerlayout = Layout::horizontal([
            Constraint::Percentage(left_pct),
            Constraint::Percentage(right_pct),
        ])
        .split(frame.area());
        let innerlayout =
            Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(outerlayout[1]);
        let processlayout =
            Layout::horizontal([Constraint::Percentage(35), Constraint::Percentage(65)])
                .split(innerlayout[0]);
        let layout = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Min(1),
            Constraint::Length(5),
        ])
        .split(outerlayout[0]);

        let help_area = layout[0];
        let input_area = layout[1];
        let footer = layout[3];

        let (log_area, heap_area) = if self.swap_panels {
            (innerlayout[1], layout[2])
        } else {
            (layout[2], innerlayout[1])
        };

        self.messages_height = log_area.height.saturating_sub(2);

        let (msg, style) = match self.input_mode {
            InputMode::Normal => (
                vec![
                    "Press ".into(),
                    "q".bold(),
                    " to exit, ".into(),
                    "e".bold(),
                    " to start editing.".bold(),
                ],
                Style::default().add_modifier(Modifier::RAPID_BLINK),
            ),
            InputMode::Editing => (
                vec![
                    "Press ".into(),
                    "Esc".bold(),
                    " to stop editing, ".into(),
                    "Enter".bold(),
                    " to record the message".into(),
                ],
                Style::default(),
            ),
        };
        let text = Text::from(Line::from(msg)).patch_style(style);
        let help_message =
            Paragraph::new(text).style(Style::default().bg(self.theme.bg).fg(self.theme.text));
        frame.render_widget(help_message, help_area);

        let input = Paragraph::new(self.input.as_str())
            .style(match self.input_mode {
                InputMode::Normal => Style::default().bg(self.theme.bg).fg(self.theme.text),
                InputMode::Editing => Style::default()
                    .bg(self.theme.bg)
                    .fg(self.theme.growth_warning),
            })
            .block(
                Block::bordered()
                    .border_style(Style::default().fg(self.theme.border))
                    .title("MVIS CLI"),
            );
        frame.render_widget(input, input_area);
        match self.input_mode {
            // Hide the cursor. `Frame` does this by default, so we don't need to do anything here
            InputMode::Normal => {}

            // Make the cursor visible and ask ratatui to put it at the specified coordinates after
            // rendering
            #[expect(clippy::cast_possible_truncation)]
            InputMode::Editing => frame.set_cursor_position(Position::new(
                // Draw the cursor at the current position in the input field.
                // This position can be controlled via the left and right arrow key
                input_area.x + self.character_index as u16 + 1,
                // Move one line down, from the border to the input line
                input_area.y + 1,
            )),
        }

        let messages_widget = Paragraph::new(self.messages.clone())
            .block(
                Block::bordered()
                    .border_style(Style::default().fg(self.theme.border))
                    .title("Output (↑/↓ to scroll)"),
            )
            .scroll((self.scroll_offset, 0))
            .wrap(Wrap { trim: false });

        frame.render_widget(messages_widget, log_area);

        let proc_lines = match &self.current_proc {
            Some(name) => {
                let mut lines = vec![
                    Line::from(Span::styled(
                        format!("Process : {}", name),
                        Style::default().fg(self.theme.text),
                    )),
                    Line::from(Span::styled(
                        format!("PID     : {}", self.current_pid.unwrap_or(0)),
                        Style::default().fg(self.theme.text),
                    )),
                    Line::from(Span::styled(
                        format!("Memory  : {} MB", self.current_memory_mb.unwrap_or(0)),
                        Style::default().fg(self.theme.text),
                    )),
                ];
                // Append alert badge
                if let Some((label, style)) = self.compute_badge() {
                    lines.push(Line::from(vec![
                        Span::raw("Status  : "),
                        Span::styled(label, style),
                    ]));
                }
                if let Some((label, style)) = self.compute_badge() {
                    lines.push(Line::from(vec![
                        Span::raw("Status  : "),
                        Span::styled(label, style),
                    ]));
                }
                if let Some((label, style)) = self.compute_watch_badge() {
                    lines.push(Line::from(Span::styled(label, style)));
                }
                lines
            }
            None => {
                let mut lines = vec![
                    Line::raw("No process scanned yet."),
                    Line::raw("Run: scan <proc> -a"),
                ];
                if let Some((label, style)) = self.compute_watch_badge() {
                    lines.push(Line::from(Span::styled(label, style)));
                }
                lines
            }
        };

        frame.render_widget(
            Paragraph::new(proc_lines)
                .style(Style::default().bg(self.theme.bg).fg(self.theme.cyan))
                .block(
                    Block::bordered()
                        .border_style(Style::default().bg(self.theme.bg).fg(self.theme.border))
                        .title("Process Info"),
                ),
            processlayout[0],
        );

        if self.focus == Focus::Tree {
            let tree_lines = render_process_tree(
                &self.alloc_tree.rows,
                self.alloc_tree.state.selected,
                self.alloc_tree.total_memory,
                &self.theme,
            );

            let inner_height = processlayout[1].height.saturating_sub(2) as usize; // minus borders
            let header_footer = 4usize;
            let visible_rows = inner_height.saturating_sub(header_footer);
            if visible_rows > 0 {
                if self.alloc_tree.state.selected < self.alloc_tree.state.scroll {
                    self.alloc_tree.state.scroll = self.alloc_tree.state.selected;
                } else if self.alloc_tree.state.selected
                    >= self.alloc_tree.state.scroll + visible_rows
                {
                    self.alloc_tree.state.scroll =
                        self.alloc_tree.state.selected + 1 - visible_rows;
                }
            }

            frame.render_widget(
                Paragraph::new(tree_lines)
                    .block(
                        Block::bordered()
                            .border_style(Style::default().bg(self.theme.bg).fg(self.theme.border))
                            .title("Process Tree [t to toggle]"),
                    )
                    .style(Style::default().bg(self.theme.bg).fg(self.theme.cyan))
                    .scroll((self.alloc_tree.state.scroll as u16, 0)),
                processlayout[1],
            );
        } else {
            if self.proc_list.items.is_empty() {
                self.refresh_proc_list();
            }

            let inner_height = processlayout[1].height.saturating_sub(2) as usize; // minus borders
            if inner_height > 0 {
                if self.proc_list.state.selected < self.proc_list.state.scroll {
                    self.proc_list.state.scroll = self.proc_list.state.selected;
                } else if self.proc_list.state.selected
                    >= self.proc_list.state.scroll + inner_height
                {
                    self.proc_list.state.scroll = self.proc_list.state.selected + 1 - inner_height;
                }
            }

            let list_lines: Vec<Line> = self
                .proc_list
                .items
                .iter()
                .enumerate()
                .map(|(i, p)| {
                    if self.focus == Focus::ProcList && i == self.proc_list.state.selected {
                        Line::from(Span::styled(
                            p.clone(),
                            Style::default()
                                .bg(self.theme.highlight_bg)
                                .fg(self.theme.highlight_fg),
                        ))
                    } else {
                        Line::from(p.clone())
                    }
                })
                .collect();

            let title = if self.focus == Focus::ProcList {
                "Process List [j/k select  Enter scan-h  i insert  r refresh]"
            } else {
                "Process List [p to select] Process Tree [t to toggle]"
            };

            frame.render_widget(
                Paragraph::new(list_lines)
                    .block(
                        Block::bordered()
                            .border_style(Style::default().bg(self.theme.bg).fg(self.theme.border))
                            .title(title),
                    )
                    .style(Style::default().bg(self.theme.bg).fg(self.theme.cyan))
                    .scroll((self.proc_list.state.scroll as u16, 0)),
                processlayout[1],
            );
        }

        if matches!(self.heap_view_mode, HeapViewMode::Chart) {
            let raw: Vec<f64> = self
                .leak_deltas
                .iter()
                .map(|d| d.net_change() as f64 / 1024.0)
                .collect();

            if raw.len() < 2 {
                frame.render_widget(
                    Paragraph::new(vec![
                        Line::raw(""),
                        Line::from(Span::styled(
                            "  Watching for leak delta...",
                            Style::default().fg(self.theme.border),
                        )),
                        Line::raw("  Need 2+ leak scans to plot."),
                        Line::raw("  Run: watch <proc> -l"),
                    ])
                    .block(
                        Block::bordered()
                            .border_style(Style::default().fg(self.theme.border))
                            .title("Leak Delta [Tab for histogram]")
                            .fg(self.theme.healthy),
                    ),
                    heap_area,
                );
            } else {
                let data: Vec<(f64, f64)> = raw
                    .iter()
                    .enumerate()
                    .map(|(i, &v)| (i as f64, v))
                    .collect();

                let max_val = raw.iter().cloned().fold(0f64, f64::max).max(1.0);
                let min_val = raw.iter().cloned().fold(0f64, f64::min).min(-1.0);
                let max_abs = max_val.abs().max(min_val.abs());
                let y_max = max_abs * 1.1;
                let y_min = -max_abs * 1.1;
                let x_max = (raw.len() - 1) as f64;

                let last_net = self.leak_deltas.last().map(|d| d.net_change()).unwrap_or(0);
                let line_color = if last_net > 0 {
                    self.theme.growth_critical
                } else {
                    self.theme.healthy
                };

                let dataset = Dataset::default()
                    .name("Net KB / sample")
                    .marker(ratatui::symbols::Marker::Braille)
                    .graph_type(ratatui::widgets::GraphType::Line)
                    .style(Style::default().fg(line_color))
                    .data(&data);

                let label_bot = format!("{:.0}KB", y_min);
                let label_top = format!("+{:.0}KB", y_max);

                let title = if let Some(last_delta) = self.leak_deltas.last() {
                    let (msg, severity) = last_delta.get_diagnostic_line();
                    let color = match severity {
                        DiagnosticSeverity::LeakSuspected => self.theme.growth_critical,
                        DiagnosticSeverity::Reclaimed => self.theme.blue,
                        DiagnosticSeverity::Healthy => self.theme.healthy,
                    };
                    let panel_w = heap_area.width as usize;
                    let short = if msg.len() + 6 > panel_w {
                        format!("  {}", &msg[..panel_w.saturating_sub(6)])
                    } else {
                        format!("  {}", msg)
                    };
                    Line::from(Span::styled(short, Style::default().fg(color)))
                } else {
                    Line::raw("Leak Delta")
                };

                frame.render_widget(
                    Chart::new(vec![dataset])
                        .block(
                            Block::bordered()
                                .border_style(Style::default().fg(self.theme.border))
                                .title(title)
                                .fg(self.theme.healthy),
                        )
                        .x_axis(
                            Axis::default()
                                .title("Samples")
                                .bounds([0.0, x_max])
                                .labels(["oldest", "newest"]),
                        )
                        .y_axis(
                            Axis::default()
                                .title("Net KB")
                                .bounds([y_min, y_max])
                                .labels([label_bot.as_str(), "0", label_top.as_str()]),
                        ),
                    heap_area,
                );
            }
        } else {
            let heap_lines = match &self.heap_history.last() {
                None => vec![Line::raw("No heap data."), Line::raw("Run: scan <proc> -h")],
                Some(snap) => {
                    let panel_height = heap_area.height as usize;
                    self.alloc_table_page_size = panel_height.saturating_sub(6);
                    let w = heap_area.width.saturating_sub(2) as usize;

                    match self.heap_view_mode {
                        HeapViewMode::Metrics => render_heap_metrics(snap, w, &self.theme),
                        HeapViewMode::Allocations => render_alloc_table(
                            snap,
                            self.alloc_table_page,
                            self.alloc_table_page_size,
                            self.alloc_table_selected,
                            &self.theme,
                        ),
                        HeapViewMode::Histogram => {
                            render_histogram(snap, w, self.histogram.state.selected, &self.theme)
                        }
                        HeapViewMode::Chart => unreachable!(),
                        HeapViewMode::PointerTree => {
                            let visible_rows = panel_height.saturating_sub(6);
                            if visible_rows > 0 {
                                if self.pointer_tree.state.selected < self.pointer_tree.state.scroll
                                {
                                    self.pointer_tree.state.scroll =
                                        self.pointer_tree.state.selected;
                                } else if self.pointer_tree.state.selected
                                    >= self.pointer_tree.state.scroll + visible_rows
                                {
                                    self.pointer_tree.state.scroll =
                                        self.pointer_tree.state.selected + 1 - visible_rows;
                                }
                            }
                            render_pointer_tree(
                                self.pointer_tree.root,
                                &self.pointer_tree.rows,
                                self.pointer_tree.state.selected,
                                &self.theme,
                            )
                        }
                        HeapViewMode::HexDump => render_hex_dump(
                            self.hex_dump.address,
                            &self.hex_dump.bytes,
                            self.hex_dump.scroll,
                            &self.theme,
                        ),
                    }
                }
            };

            let heap_scroll = match self.heap_view_mode {
                HeapViewMode::PointerTree => self.pointer_tree.state.scroll as u16,
                _ => 0,
            };

            frame.render_widget(
                Paragraph::new(heap_lines)
                    .block(
                        Block::bordered()
                            .border_style(Style::default().fg(self.theme.border))
                            .title(match self.heap_view_mode {
                                HeapViewMode::Metrics => "Heap View [Tab for table]",
                                HeapViewMode::Allocations => {
                                    "Heap View [Tab for chart · 'd' inspect]"
                                }
                                HeapViewMode::Histogram => {
                                    "Allocation Histogram [Tab: metrics · Enter: jump]"
                                }
                                HeapViewMode::Chart => unreachable!(),
                                HeapViewMode::PointerTree => {
                                    "Pointer Tree [j/k nav · Enter expand/collapse · Esc back]"
                                }
                                HeapViewMode::HexDump => "Memory Inspector [j/k scroll · Esc back]",
                            })
                            .fg(self.theme.healthy),
                    )
                    .scroll((heap_scroll, 0)),
                heap_area,
            );

            if let Some(p) = &self.prompt {
                let area = frame.area();
                let w = 40.min(area.width.saturating_sub(4));
                let h = (p.fields.len() as u16 + 4).min(area.height.saturating_sub(4));
                let x = (area.width.saturating_sub(w)) / 2;
                let y = (area.height.saturating_sub(h)) / 2;
                let popup = ratatui::layout::Rect::new(x, y, w, h);

                frame.render_widget(ratatui::widgets::Clear, popup);

                let title = match p.kind {
                    PromptKind::Leak => "leak",
                    PromptKind::LeakM => "leak-m",
                    PromptKind::Watch => "watch",
                };

                let mut lines = vec![Line::raw(format!("proc: {}", p.proc_name)), Line::raw("")];
                for (i, f) in p.fields.iter().enumerate() {
                    let style = if i == p.selected {
                        Style::default()
                            .bg(self.theme.highlight_bg)
                            .fg(self.theme.highlight_fg)
                    } else {
                        Style::default().fg(self.theme.text)
                    };
                    lines.push(Line::from(Span::styled(
                        format!("{}: {}", f.label, f.value),
                        style,
                    )));
                }
                lines.push(Line::raw(""));
                lines.push(Line::raw("Tab next  Enter confirm  Esc cancel"));

                frame.render_widget(
                    Paragraph::new(lines)
                        .block(
                            Block::bordered()
                                .border_style(Style::default().fg(self.theme.growth_warning))
                                .title(title),
                        )
                        .style(Style::default().bg(self.theme.bg).fg(self.theme.text)),
                    popup,
                );
            }
        }

        let footer_text = match self.input_mode {
            InputMode::Normal => {
                let mut spans = vec![
                    Span::styled(
                        " NORMAL ",
                        Style::default().fg(self.theme.bg).bg(self.theme.healthy),
                    ),
                    Span::raw("  "),
                ];
                let hint = |k: &str, desc: &str| -> Vec<Span<'static>> {
                    let vector = vec![
                        Span::styled(
                            k.to_string(),
                            Style::default()
                                .fg(self.theme.growth_warning)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::raw(format!(" {}  •  ", desc)),
                    ];
                    vector
                };
                spans.extend(hint("e", "edit"));
                spans.extend(hint("q", "quit"));
                spans.extend(hint("?", "help"));
                match self.focus {
                    Focus::ProcList => {
                        spans.extend(hint("j/k", "select"));
                        spans.extend(hint("Enter", "scan-h"));
                        spans.extend(hint("a/v", "scan"));
                        spans.extend(hint("b/d", "baseline/diff"));
                        spans.extend(hint("l/L/w", "leak/leak-m/watch"));
                        spans.extend(hint("i", "insert name"));
                        spans.extend(hint("r", "refresh"));
                    }
                    Focus::Tree => {
                        spans.extend(hint("j/k", "select"));
                        spans.extend(hint("Enter", "expand/collapse"));
                    }
                    Focus::AllocTable => {
                        spans.extend(hint("j/k", "select row"));
                        spans.extend(hint("[/]", "page"));
                        spans.extend(hint("Tab", "heap view"));
                    }
                }
                spans.extend(hint("t/p", "toggle tree/proclist"));
                spans.extend(hint("x", "swap output/heap panels"));
                spans.extend(hint("S", "settings"));
                Line::from(spans)
            }
            InputMode::Editing => Line::from(vec![
                Span::styled(
                    " INSERT ",
                    Style::default()
                        .fg(self.theme.bg)
                        .bg(self.theme.growth_warning),
                ),
                Span::raw("  try: "),
                Span::styled("scan <proc_name> -a", Style::default().fg(self.theme.cyan)),
                Span::raw("  •  "),
                Span::styled("scan <proc_name> -h", Style::default().fg(self.theme.cyan)),
                Span::raw("  •  "),
                Span::styled("leak <proc_name> 10", Style::default().fg(self.theme.cyan)),
                Span::raw("  •  "),
                Span::styled("watch <proc_name> -l", Style::default().fg(self.theme.cyan)),
                Span::raw("  •  "),
                Span::styled("list", Style::default().fg(self.theme.cyan)),
                Span::raw("  •  "),
                Span::styled(
                    "Esc",
                    Style::default()
                        .fg(self.theme.growth_warning)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" to exit insert"),
            ]),
        };

        frame.render_widget(
            Paragraph::new(footer_text)
                .block(Block::new().borders(Borders::ALL))
                .wrap(Wrap { trim: true }),
            footer,
        );

        if self.settings_view.open {
            let area = frame.area();
            let w = 56.min(area.width.saturating_sub(4));
            let h = (SETTINGS_ROW_COUNT as u16 + 5).min(area.height.saturating_sub(4));
            let x = (area.width.saturating_sub(w)) / 2;
            let y = (area.height.saturating_sub(h)) / 2;
            let popup = ratatui::layout::Rect::new(x, y, w, h);
            frame.render_widget(ratatui::widgets::Clear, popup);

            let row_style = |i: usize, theme: &Theme| {
                if i == self.settings_view.state.selected {
                    Style::default()
                        .bg(theme.highlight_bg)
                        .fg(theme.highlight_fg)
                } else {
                    Style::default().fg(theme.text)
                }
            };

            let mut lines = vec![
                Line::from(Span::styled(
                    format!(
                        "{:<22} {}",
                        "Watch interval (ms)", self.settings_view.settings.watch_interval_millis
                    ),
                    row_style(0, &self.theme),
                )),
                Line::from(Span::styled(
                    format!(
                        "{:<22} {:?}",
                        "Theme", self.settings_view.settings.theme_kind
                    ),
                    row_style(1, &self.theme),
                )),
                Line::from(Span::styled(
                    format!(
                        "{:<22} {:.1}",
                        "Badge: Caution MB/s", self.settings_view.settings.badge_caution_mb_s
                    ),
                    row_style(2, &self.theme),
                )),
                Line::from(Span::styled(
                    format!(
                        "{:<22} {:.1}",
                        "Badge: Warning MB/s", self.settings_view.settings.badge_warning_mb_s
                    ),
                    row_style(3, &self.theme),
                )),
                Line::from(Span::styled(
                    format!(
                        "{:<22} {:.1}",
                        "Badge: Critical MB/s", self.settings_view.settings.badge_critical_mb_s
                    ),
                    row_style(4, &self.theme),
                )),
            ];
            for (i, mode) in HEAP_VIEW_ORDER.iter().enumerate() {
                let mark = if self.settings_view.settings.enabled_views[i] {
                    "[x]"
                } else {
                    "[ ]"
                };
                lines.push(Line::from(Span::styled(
                    format!(
                        "{:<22} {}",
                        format!("View: {}", heap_view_label(*mode)),
                        mark
                    ),
                    row_style(5 + i, &self.theme),
                )));
            }
            lines.push(Line::from(Span::styled(
                format!(
                    "{:<22} {}",
                    "Default view",
                    heap_view_label(self.settings_view.settings.default_view())
                ),
                row_style(9, &self.theme),
            )));
            lines.push(Line::raw(""));
            lines.push(Line::raw("j/k select  h/l adjust  Enter toggle  Esc close"));

            frame.render_widget(
                Paragraph::new(lines)
                    .block(
                        Block::bordered()
                            .border_style(Style::default().fg(self.theme.growth_warning))
                            .title("Settings"),
                    )
                    .style(Style::default().bg(self.theme.bg).fg(self.theme.text)),
                popup,
            );
        }
    }
}

fn render_pointer_tree(
    root: Option<usize>,
    rows: &[PointerTreeRow],
    selected: usize,
    theme: &crate::ui::theme::Theme,
) -> Vec<Line<'static>> {
    let mut lines = vec![];

    let Some(root_addr) = root else {
        lines.push(Line::raw("No block selected."));
        lines.push(Line::raw("In Allocations view, select a [PTR]/[REF]"));
        lines.push(Line::raw("row and press Enter to open its tree."));
        return lines;
    };

    if rows.is_empty() {
        lines.push(Line::raw(format!(
            "0x{:x} has no resolved pointers.",
            root_addr
        )));
        return lines;
    }

    lines.push(Line::from(vec![
        Span::raw("Root: "),
        Span::styled(
            format!("0x{:x}", root_addr),
            Style::default()
                .fg(theme.magenta)
                .add_modifier(Modifier::BOLD),
        ),
    ]));
    lines.push(Line::raw("─".repeat(50)));

    for (i, row) in rows.iter().enumerate() {
        let indent = "  ".repeat(row.depth);
        let prefix = if row.is_cycle {
            "[~] "
        } else if row.is_dangling {
            "[!] "
        } else if row.has_children {
            if row.is_collapsed { "[+] " } else { "[-] " }
        } else if row.depth > 0 {
            "├─  "
        } else {
            "    "
        };

        let color = if row.is_dangling {
            theme.growth_critical
        } else if row.is_cycle {
            theme.cyan
        } else if row.is_shared {
            theme.growth_warning
        } else if row.is_leaf {
            theme.healthy
        } else {
            theme.text
        };

        let style = if i == selected {
            Style::default()
                .bg(theme.highlight_bg)
                .fg(theme.highlight_fg)
        } else {
            Style::default().fg(color)
        };

        let label = if row.is_dangling {
            format!(
                "{indent}{prefix}0x{:x}  [dangling → freed block]",
                row.address
            )
        } else if row.is_cycle {
            format!("{indent}{prefix}0x{:x}  [cycle]", row.address)
        } else if row.is_shared {
            format!("{indent}{prefix}0x{:x}  [shared — see above]", row.address)
        } else {
            format!(
                "{indent}{prefix}0x{:x}  {}",
                row.address,
                format_bytes(row.size as u64)
            )
        };

        lines.push(Line::from(Span::styled(label, style)));
    }

    lines.push(Line::raw("─".repeat(50)));
    lines.push(Line::from(vec![
        Span::styled(
            "j/k",
            Style::default()
                .fg(theme.growth_warning)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" navigate  "),
        Span::styled(
            "Enter",
            Style::default()
                .fg(theme.growth_warning)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" expand/collapse  "),
        Span::styled(
            "Esc",
            Style::default()
                .fg(theme.growth_warning)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" back"),
    ]));

    lines
}

fn render_hex_dump(
    address: Option<usize>,
    bytes: &[u8],
    scroll: usize,
    theme: &crate::ui::theme::Theme,
) -> Vec<Line<'static>> {
    let mut lines = vec![];

    let Some(addr) = address else {
        lines.push(Line::raw("No memory address selected for inspection."));
        lines.push(Line::raw("Run: dump <proc/pid> <address> [length]"));
        lines.push(Line::raw("Or select an allocation block and press 'd'."));
        return lines;
    };

    if bytes.is_empty() {
        lines.push(Line::raw(format!(
            "0x{:x}: <unable to read memory bytes>",
            addr
        )));
        return lines;
    }

    lines.push(Line::from(vec![
        Span::raw("Address: "),
        Span::styled(
            format!("0x{:x}", addr),
            Style::default().fg(theme.cyan).add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!("  ({} bytes)", bytes.len())),
    ]));
    lines.push(Line::raw("─".repeat(60)));

    let dump_lines = format_hex_dump(addr, bytes);
    for l in dump_lines.into_iter().skip(scroll) {
        lines.push(Line::from(Span::styled(l, Style::default().fg(theme.text))));
    }

    lines.push(Line::raw("─".repeat(60)));
    lines.push(Line::from(vec![
        Span::styled(
            "j/k",
            Style::default()
                .fg(theme.growth_warning)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" scroll  "),
        Span::styled(
            "d",
            Style::default()
                .fg(theme.growth_warning)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" inspect block  "),
        Span::styled(
            "Esc",
            Style::default()
                .fg(theme.growth_warning)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" back"),
    ]));

    lines
}

fn render_heap_metrics(
    snap: &HeapSnapshot,
    width: usize,
    theme: &crate::ui::theme::Theme,
) -> Vec<Line<'static>> {
    let mut lines = vec![];
    let bar_w = width.saturating_sub(20);

    // fragmentation bar
    let frag_fill = ((snap.fragmentation / 100.0) * bar_w as f64) as usize;
    let frag_color = if snap.fragmentation > 50.0 {
        theme.growth_critical
    } else if snap.fragmentation > 25.0 {
        theme.growth_warning
    } else {
        theme.healthy
    };

    lines.push(Line::raw("── High-Level Metrics ──────────────────"));
    lines.push(Line::from(vec![
        Span::raw(format!("Frag {:>3.0}%     ", snap.fragmentation)),
        Span::styled("█".repeat(frag_fill), Style::default().fg(frag_color)),
        Span::styled(
            "░".repeat(bar_w - frag_fill),
            Style::default().fg(theme.border),
        ),
    ]));

    // used/free bar
    let total = snap.used_bytes + snap.free_bytes;
    let used_fill = ((snap.used_bytes as f64 / total as f64) * bar_w as f64) as usize;
    lines.push(Line::from(vec![
        Span::raw("Used          "),
        Span::styled("█".repeat(used_fill), Style::default().fg(theme.magenta)),
        Span::styled(
            "░".repeat(bar_w - used_fill),
            Style::default().fg(theme.border),
        ),
        Span::raw(format!("  {}", format_bytes(snap.used_bytes as u64))),
    ]));
    lines.push(Line::from(vec![
        Span::raw("Free          "),
        Span::styled(
            "█".repeat(bar_w - used_fill),
            Style::default().fg(theme.blue),
        ),
        Span::styled("░".repeat(used_fill), Style::default().fg(theme.border)),
        Span::raw(format!("  {}", format_bytes(snap.free_bytes as u64))),
    ]));

    lines.push(Line::raw(""));
    lines.push(Line::raw(format!(
        "Total blocks : {}",
        snap.used_blocks + snap.free_blocks
    )));
    lines.push(Line::raw(format!("Used blocks  : {}", snap.used_blocks)));
    lines.push(Line::raw(format!("Free blocks  : {}", snap.free_blocks)));
    lines.push(Line::raw(format!(
        "Largest used : {}",
        format_bytes(snap.largest_used as u64)
    )));
    lines.push(Line::raw(format!(
        "Largest free : {}",
        format_bytes(snap.largest_free as u64)
    )));
    lines.push(Line::raw(""));

    let (msg, color) = if snap.fragmentation > 50.0 {
        ("⚠ High fragmentation", theme.growth_critical)
    } else if snap.fragmentation > 25.0 {
        ("~ Moderate fragmentation", theme.growth_warning)
    } else {
        ("✓ Heap healthy", theme.healthy)
    };
    lines.push(Line::from(Span::styled(msg, Style::default().fg(color))));
    lines.push(Line::raw(""));
    lines.push(Line::raw("Tab → Allocation Table"));
    lines
}

fn render_alloc_table(
    snap: &HeapSnapshot,
    page: usize,
    page_size: usize,
    selected: usize,
    theme: &crate::ui::theme::Theme,
) -> Vec<Line<'static>> {
    let mut lines = vec![];

    let used_blocks: Vec<_> = {
        let mut b: Vec<_> = snap.blocks.iter().filter(|b| !b.is_free).collect();
        b.sort_by(|a, b| b.size.cmp(&a.size)); // largest first
        b
    };

    let total_pages = used_blocks.len().div_ceil(page_size);
    let start = page * page_size;
    let page_blocks: Vec<_> = used_blocks.iter().skip(start).take(page_size).collect();

    lines.push(Line::raw(format!(
        "── Allocations  Page {}/{}  ({} total) ──",
        page + 1,
        total_pages,
        used_blocks.len()
    )));
    lines.push(Line::raw(format!(
        "{:<5} {:<18} {:<12} {:<8} {:<6} {}",
        "#", "ADDRESS", "SIZE", "NOTE", "PROTECT", "TAG"
    )));
    lines.push(Line::raw("─".repeat(60)));

    for (i, block) in page_blocks.iter().enumerate() {
        let idx = start + i + 1;
        let note = if block.size >= 1024 * 1024 {
            "LARGE"
        } else if block.size >= 65536 {
            "medium"
        } else {
            ""
        };
        let protect = if block.vm_protect == RegionProtect::ReadWrite {
            "RW"
        } else if block.vm_protect == RegionProtect::Readonly {
            "R"
        } else if block.vm_protect == RegionProtect::Execute {
            "X"
        } else if block.vm_protect == RegionProtect::Guard {
            "G"
        } else {
            ""
        };

        let tag = if snap.pointer_blocks.contains(&block.address)
            && snap.referenced_blocks.contains(&block.address)
        {
            "[PTR+REF]" // contains pointers AND is pointed to by others
        } else if snap.pointer_blocks.contains(&block.address) {
            "[PTR]" // contains pointers to other blocks
        } else if snap.referenced_blocks.contains(&block.address) {
            "[REF]" // pointed to by other blocks
        } else {
            ""
        };

        let style = if i == selected {
            Style::default().bg(theme.border).fg(theme.text)
        } else if block.vm_protect == RegionProtect::Execute || block.size >= 1024 * 1024 {
            Style::default().fg(theme.growth_critical)
        } else if block.size >= 65536 {
            Style::default().fg(theme.growth_warning)
        } else {
            Style::default()
        };

        lines.push(Line::from(Span::styled(
            format!(
                "{:<5} {:<18} {:<12} {:<8} {:<6} {}",
                idx,
                format!("0x{:x}", block.address),
                format_bytes(block.size as u64),
                note,
                protect,
                tag,
            ),
            style,
        )));
    }

    lines.push(Line::raw(""));
    lines.push(Line::raw(
        "[ prev page   ] next page   J/K select row   Tab → Metrics",
    ));
    lines
}

fn render_process_tree(
    rows: &[TreeDisplayRow],
    selected: usize,
    total_memory: u64,
    theme: &crate::ui::theme::Theme,
) -> Vec<Line<'static>> {
    let mut lines = vec![];

    if rows.is_empty() {
        lines.push(Line::raw("No process scanned yet."));
        lines.push(Line::raw("Run: scan <proc> -h"));
        lines.push(Line::raw("Then press t for tree view."));
        return lines;
    }

    lines.push(Line::from(vec![
        Span::raw("Total group memory: "),
        Span::styled(
            format_bytes(total_memory),
            Style::default()
                .fg(theme.magenta)
                .add_modifier(Modifier::BOLD),
        ),
    ]));
    lines.push(Line::raw("─".repeat(50)));

    for (i, row) in rows.iter().enumerate() {
        let indent = "  ".repeat(row.depth);
        let prefix = if row.has_children {
            if row.is_collapsed { "[+] " } else { "[-] " }
        } else if row.depth > 0 {
            "├─  "
        } else {
            "    "
        };

        let mem_mb = row.memory as f64 / (1024.0 * 1024.0);
        let health_color = if mem_mb >= 500.0 {
            theme.growth_critical
        } else if mem_mb >= 100.0 {
            theme.growth_warning
        } else {
            theme.healthy
        };

        let style = if i == selected {
            Style::default()
                .bg(theme.highlight_bg)
                .fg(theme.highlight_fg)
        } else {
            Style::default().fg(health_color)
        };

        let line = Line::from(vec![
            Span::styled(format!("{indent}{prefix}{:<25}", row.name), style),
            Span::styled(
                format!(" PID:{:<8}", row.pid),
                if i == selected {
                    style
                } else {
                    Style::default().fg(theme.text)
                },
            ),
            Span::styled(
                format!(" {}", format_bytes(row.memory)),
                if i == selected {
                    style
                } else {
                    Style::default().fg(health_color)
                },
            ),
        ]);
        lines.push(line);
    }

    lines.push(Line::raw("─".repeat(50)));
    lines.push(Line::from(vec![
        Span::styled(
            "j/k",
            Style::default()
                .fg(theme.growth_warning)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" navigate  "),
        Span::styled(
            "Enter",
            Style::default()
                .fg(theme.growth_warning)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" expand/collapse  "),
        Span::styled(
            "t",
            Style::default()
                .fg(theme.growth_warning)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" back to list"),
    ]));

    lines
}

fn render_histogram(
    snap: &HeapSnapshot,
    width: usize,
    selected: usize,
    theme: &crate::ui::theme::Theme,
) -> Vec<Line<'static>> {
    let mut lines = vec![];

    let used_blocks: Vec<_> = snap.blocks.iter().filter(|b| !b.is_free).collect();
    let total = used_blocks.len();

    let mut counts = [0usize; SIZE_BUCKETS.len()];
    let mut bytes = [0u64; SIZE_BUCKETS.len()];
    for block in &used_blocks {
        for (i, &(_, lo, hi)) in SIZE_BUCKETS.iter().enumerate() {
            if block.size > lo && block.size <= hi {
                counts[i] += 1;
                bytes[i] += block.size as u64;
                break;
            }
        }
    }

    let max_count = counts.iter().copied().max().unwrap_or(0).max(1);
    let label_w = SIZE_BUCKETS
        .iter()
        .map(|(l, _, _)| l.len())
        .max()
        .unwrap_or(0);
    let count_w = 6;
    let bar_w = width.saturating_sub(label_w + count_w + 4).max(4);

    lines.push(Line::raw(format!(
        "── Allocation Size Distribution  ({total} used blocks) ──"
    )));
    lines.push(Line::raw(""));

    for (i, &(label, _, _)) in SIZE_BUCKETS.iter().enumerate() {
        let count = counts[i];
        let fill = (((count as f64 / max_count as f64) * bar_w as f64).round() as usize).min(bar_w);

        // colour ramp mirrors the LARGE/medium thresholds from render_alloc_table
        let color = if i >= 4 {
            theme.growth_critical
        } else if i >= 2 {
            theme.growth_warning
        } else {
            theme.healthy
        };

        let bar_style = if i == selected {
            Style::default()
                .bg(theme.highlight_bg)
                .fg(theme.highlight_fg)
        } else {
            Style::default().fg(color)
        };
        let label_style = if i == selected {
            Style::default().bg(theme.border).fg(theme.text)
        } else {
            Style::default().fg(theme.text)
        };

        lines.push(Line::from(vec![
            Span::styled(format!("{label:<label_w$} "), label_style),
            Span::styled("█".repeat(fill), bar_style),
            Span::styled("░".repeat(bar_w - fill), Style::default().fg(theme.border)),
            Span::styled(format!(" {count:>count_w$}"), label_style),
        ]));
    }

    lines.push(Line::raw(""));
    if let Some(&(label, _, _)) = SIZE_BUCKETS.get(selected) {
        lines.push(Line::from(Span::styled(
            format!(
                "Selected: {label}  —  {} blocks, {} total",
                counts[selected],
                format_bytes(bytes[selected])
            ),
            Style::default().fg(theme.cyan),
        )));
    }
    lines.push(Line::raw(
        "j/k select bucket   Enter → jump to allocations   Tab → metrics",
    ));

    lines
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::collections::HashSet;

    use super::*;

    // ── helpers ─────────────────────────────────────────────────────────────

    fn make_app() -> App {
        App::new(ThemeKind::default())
    }

    fn make_app_with_heap() -> App {
        let mut app = make_app();
        app.heap_history.push(HeapSnapshot {
            fragmentation: 30.0,
            used_blocks: 10,
            free_blocks: 5,
            used_bytes: 1024,
            free_bytes: 512,
            largest_free: 256,
            largest_used: 512,
            blocks: vec![
                HeapBlock {
                    address: 0x1000,
                    size: 512,
                    is_free: false,
                    vm_protect: RegionProtect::ReadWrite,
                },
                HeapBlock {
                    address: 0x2000,
                    size: 256,
                    is_free: false,
                    vm_protect: RegionProtect::ReadWrite,
                },
                HeapBlock {
                    address: 0x3000,
                    size: 128,
                    is_free: true,
                    vm_protect: RegionProtect::ReadWrite,
                },
            ],
            pointer_blocks: HashSet::new(),
            referenced_blocks: HashSet::new(),
            pointer_edges: HashMap::new(),
        });
        app
    }

    #[test]
    fn clear_command_removes_output_and_resets_scroll() {
        let mut app = App::new(ThemeKind::default());
        app.messages_height = 1;
        app.push_message("old output".into());
        app.scroll_down();

        app.input = "clear".into();
        app.character_index = app.input.chars().count();
        app.submit_message();

        assert!(app.messages.is_empty());
        assert_eq!(app.scroll_offset, 0);
    }

    #[test]
    fn help_mentions_clear_command() {
        let mut app = App::new(ThemeKind::default());

        app.input = "help".into();
        app.character_index = app.input.chars().count();
        app.submit_message();

        assert!(
            app.messages
                .iter()
                .any(|line| line.to_string().contains("clear"))
        );
    }

    // ── input / cursor ───────────────────────────────────────────────────────

    #[test]
    fn enter_char_advances_cursor() {
        let mut app = make_app();
        app.enter_char('h');
        app.enter_char('i');
        assert_eq!(app.input, "hi");
        assert_eq!(app.character_index, 2);
    }

    #[test]
    fn delete_char_removes_char_before_cursor() {
        let mut app = make_app();
        app.enter_char('h');
        app.enter_char('i');
        app.delete_char();
        assert_eq!(app.input, "h");
        assert_eq!(app.character_index, 1);
    }

    #[test]
    fn delete_char_at_start_is_noop() {
        let mut app = make_app();
        app.enter_char('x');
        app.move_cursor_left();
        app.delete_char();
        assert_eq!(app.input, "x");
        assert_eq!(app.character_index, 0);
    }

    #[test]
    fn move_cursor_left_clamps_at_zero() {
        let mut app = make_app();
        app.move_cursor_left();
        assert_eq!(app.character_index, 0);
    }

    #[test]
    fn move_cursor_right_clamps_at_end() {
        let mut app = make_app();
        app.enter_char('a');
        app.move_cursor_right();
        assert_eq!(app.character_index, 1);
    }

    #[test]
    fn submit_message_clears_input_and_resets_cursor() {
        let mut app = make_app();
        app.enter_char('h');
        app.enter_char('i');
        app.submit_message();
        assert!(app.input.is_empty());
        assert_eq!(app.character_index, 0);
    }

    #[test]
    fn submit_empty_input_does_nothing() {
        let mut app = make_app();
        let initial_len = app.messages.len();
        app.submit_message();
        assert_eq!(app.messages.len(), initial_len);
    }

    // ── scrolling ────────────────────────────────────────────────────────────

    #[test]
    fn scroll_up_does_not_underflow() {
        let mut app = make_app();
        app.scroll_up();
        assert_eq!(app.scroll_offset, 0);
    }

    #[test]
    fn scroll_down_increments_offset() {
        let mut app = make_app();
        let before = app.scroll_offset;
        app.scroll_down();
        assert_eq!(app.scroll_offset, before + 1);
    }

    #[test]
    fn push_message_auto_scrolls_when_full() {
        let mut app = make_app();
        app.messages_height = 2;
        app.push_message("line 1".into());
        app.push_message("line 2".into());
        app.push_message("line 3".into()); // overflows height
        // scroll_offset should have been bumped to keep the last line visible
        assert!(app.scroll_offset > 0);
    }

    // ── heap view ────────────────────────────────────────────────────────────

    #[test]
    fn tab_toggles_heap_view_mode() {
        let mut app = make_app();
        assert!(matches!(app.heap_view_mode, HeapViewMode::Metrics));
        app.heap_view_mode = HeapViewMode::Allocations;
        assert!(matches!(app.heap_view_mode, HeapViewMode::Allocations));
        app.heap_view_mode = HeapViewMode::Metrics;
        assert!(matches!(app.heap_view_mode, HeapViewMode::Metrics));
    }

    // ── pagination ───────────────────────────────────────────────────────────

    #[test]
    fn prev_page_does_not_underflow() {
        let mut app = make_app_with_heap();
        app.alloc_table_page = 0;
        app.prev_page();
        assert_eq!(app.alloc_table_page, 0);
    }

    #[test]
    fn next_page_clamps_at_last_page() {
        let mut app = make_app_with_heap();
        app.alloc_table_page_size = 10;
        app.next_page();
        assert_eq!(app.alloc_table_page, 0);
    }

    #[test]
    fn next_page_advances_when_more_blocks_exist() {
        let mut app = make_app_with_heap();
        app.alloc_table_page_size = 1;
        app.next_page();
        assert_eq!(app.alloc_table_page, 1);
    }

    #[test]
    fn prev_page_after_next_returns_to_zero() {
        let mut app = make_app_with_heap();
        app.alloc_table_page_size = 1;
        app.next_page();
        app.prev_page();
        assert_eq!(app.alloc_table_page, 0);
    }

    #[test]
    fn page_change_resets_selected_row() {
        let mut app = make_app_with_heap();
        app.alloc_table_page_size = 1;
        app.alloc_table_selected = 5;
        app.next_page();
        assert_eq!(app.alloc_table_selected, 0);
    }
    // ── row selection ────────────────────────────────────────────────────────

    #[test]
    fn select_next_row_increments() {
        let mut app = make_app();
        app.alloc_table_page_size = 5;
        app.select_next_row();
        assert_eq!(app.alloc_table_selected, 1);
    }

    #[test]
    fn select_next_row_clamps_at_page_end() {
        let mut app = make_app();
        app.alloc_table_page_size = 3;
        app.alloc_table_selected = 2; // already at last row in page
        app.select_next_row();
        assert_eq!(app.alloc_table_selected, 2);
    }

    #[test]
    fn select_prev_row_does_not_underflow() {
        let mut app = make_app();
        app.alloc_table_selected = 0;
        app.select_prev_row();
        assert_eq!(app.alloc_table_selected, 0);
    }

    #[test]
    fn select_prev_row_decrements() {
        let mut app = make_app();
        app.alloc_table_selected = 3;
        app.select_prev_row();
        assert_eq!(app.alloc_table_selected, 2);
    }

    #[test]
    fn test_compute_badge_styles() {
        let mut app = make_app();

        // No leaks
        assert!(app.compute_badge().is_none());

        // Healthy (Net <= 0)
        app.leak_deltas.push(LeakDelta {
            allocated_bytes: 1000,
            freed_bytes: 1000,
        });
        app.leak_deltas.push(LeakDelta {
            allocated_bytes: 1000,
            freed_bytes: 2000,
        });
        let badge = app.compute_badge().unwrap();
        assert!(badge.0.contains("HEALTHY"));
        assert_eq!(badge.1.fg.unwrap(), app.theme.healthy);

        // Yellow Warning (> 2 MB/s)
        app.leak_deltas.push(LeakDelta {
            allocated_bytes: 5 * 1024 * 1024,
            freed_bytes: 0,
        });
        let badge = app.compute_badge().unwrap();
        assert!(badge.0.contains("CAUTION"));
        assert_eq!(badge.1.fg.unwrap(), app.theme.growth_warning);

        // Red Warning (> 20 MB/s)
        app.leak_deltas.push(LeakDelta {
            allocated_bytes: 50 * 1024 * 1024,
            freed_bytes: 0,
        });
        let badge = app.compute_badge().unwrap();
        assert!(badge.0.contains("WARNING"));
        assert_eq!(badge.1.fg.unwrap(), app.theme.growth_critical);

        // Red Critical (> 100 MB/s)
        app.leak_deltas.push(LeakDelta {
            allocated_bytes: 150 * 1024 * 1024,
            freed_bytes: 0,
        });
        let badge = app.compute_badge().unwrap();
        assert!(badge.0.contains("CRITICAL"));
        assert_eq!(badge.1.fg.unwrap(), app.theme.growth_critical);
    }

    #[test]
    fn watch_badge_shows_target_and_mode() {
        let mut app = make_app();
        assert!(app.compute_watch_badge().is_none());

        app.watch_target = Some("notepad.exe".into());
        app.watch_mode = Some("-l".into());
        let (label, _) = app.compute_watch_badge().unwrap();
        assert!(label.contains("notepad.exe"));
        assert!(label.contains("-l"));
    }

    // ── tree view ────────────────────────────────────────────────────────────

    fn make_tree_rows() -> Vec<TreeDisplayRow> {
        let vector = vec![
            TreeDisplayRow {
                pid: 100,
                name: "chrome.exe".into(),
                memory: 200 * 1024 * 1024,
                depth: 0,
                has_children: true,
                is_collapsed: false,
            },
            TreeDisplayRow {
                pid: 101,
                name: "chrome.exe".into(),
                memory: 100 * 1024 * 1024,
                depth: 1,
                has_children: false,
                is_collapsed: false,
            },
            TreeDisplayRow {
                pid: 102,
                name: "chrome.exe".into(),
                memory: 50 * 1024 * 1024,
                depth: 1,
                has_children: false,
                is_collapsed: false,
            },
        ];
        vector
    }

    #[test]
    fn toggle_tree_view_flips_state() {
        let mut app = make_app();
        assert_eq!(app.focus, Focus::AllocTable);

        app.set_focus(Focus::Tree);
        assert_eq!(app.focus, Focus::Tree);

        app.set_focus(Focus::Tree); // pressing 't' again toggles back
        assert_eq!(app.focus, Focus::AllocTable);
    }

    #[test]
    fn tree_select_next_increments() {
        let mut app = make_app();
        app.alloc_tree.rows = make_tree_rows();
        app.alloc_tree.state.selected = 0;
        app.alloc_tree.state.next(app.alloc_tree.rows.len(), false);
        assert_eq!(app.alloc_tree.state.selected, 1);
    }

    #[test]
    fn tree_select_next_clamps_at_end() {
        let mut app = make_app();
        app.alloc_tree.rows = make_tree_rows();
        app.alloc_tree.state.selected = 2;
        app.alloc_tree.state.next(app.alloc_tree.rows.len(), false);
        assert_eq!(app.alloc_tree.state.selected, 2);
    }

    #[test]
    fn tree_select_prev_decrements() {
        let mut app = make_app();
        app.alloc_tree.rows = make_tree_rows();
        app.alloc_tree.state.selected = 2;
        app.alloc_tree.state.prev(app.alloc_tree.rows.len(), false);
        assert_eq!(app.alloc_tree.state.selected, 1);
    }

    #[test]
    fn tree_select_prev_does_not_underflow() {
        let mut app = make_app();
        app.alloc_tree.rows = make_tree_rows();
        app.alloc_tree.state.selected = 0;
        app.alloc_tree.state.prev(app.alloc_tree.rows.len(), false);
        assert_eq!(app.alloc_tree.state.selected, 0);
    }

    #[test]
    fn render_process_tree_empty_shows_hint() {
        let theme = ThemeKind::default().theme();
        let lines = render_process_tree(&[], 0, 0, &theme);
        assert!(lines.iter().any(|l| l.to_string().contains("No process")));
    }

    #[test]
    fn render_process_tree_shows_total_memory() {
        let theme = ThemeKind::default().theme();
        let rows = make_tree_rows();
        let total = 350 * 1024 * 1024;
        let lines = render_process_tree(&rows, 0, total, &theme);
        assert!(
            lines
                .iter()
                .any(|l| l.to_string().contains("Total group memory"))
        );
    }
    #[test]
    fn swap_panels_toggles() {
        let mut app = make_app();
        assert!(!app.swap_panels);
        app.swap_panels = !app.swap_panels;
        assert!(app.swap_panels);
    }
}
