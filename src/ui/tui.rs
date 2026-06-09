use color_eyre::Result;
use crossterm::event::{self, KeyCode, KeyEventKind};
use ratatui::layout::{Constraint, Layout, Position};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::Span;
use ratatui::text::{Line, Text};
use ratatui::widgets::{Axis, Chart, Dataset, Wrap};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::{DefaultTerminal, Frame};

use super::commands;
use super::render::format_size;
use crate::core::delta::{DiagnosticSeverity, LeakDelta};
use crate::types::{HeapBlock, RegionProtect};
use crate::ui::commands::ScanResult;

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
pub fn tui_main() -> Result<()> {
    color_eyre::install()?;
    let terminal = ratatui::init(); // replaces ratatui::run
    let result = App::new().run(terminal);
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
}

/// App holds the state of the application
struct App {
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
    leak_deltas: Vec<LeakDelta>,
}
enum HeapViewMode {
    Metrics,     // high-level view
    Allocations, // table view
    Chart,       // Chart
}
enum InputMode {
    Normal,
    Editing,
}

//macro_rules! run_command {
//    ($self:expr, $command:expr) => {
//        $self.handle_command($command);
//    };
//}

impl App {
    fn new() -> Self {
        let (tx, rx) = std::sync::mpsc::channel();
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
            leak_deltas: vec![],
        };
        app.push_message("mvis ready. type 'help' for commands.".into());
        app
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
    fn handle_command(&mut self, parts: Vec<&str>) {
        match parts.clone().as_slice() {
            ["baseline", _proc] => {
                let query = "scan".to_string();
                let proc = _proc.to_string();
                let mode = "-h".to_string();
                let tx = self.tx.clone();
                std::thread::spawn(move || {
                    let parts_ref: Vec<&str> = vec![&query, &proc, &mode];
                    match commands::scan(parts_ref) {
                        Ok(result) => {
                            tx.send(AppEvent::BaseLine(result)).ok();
                            tx.send(AppEvent::Output(Line::raw(format!("Baseline set"))))
                                .ok();
                        }
                        Err(e) => {
                            tx.send(AppEvent::Output(Line::raw(format!("{}", e)))).ok();
                        }
                    };
                });
            }
            ["diff", _proc] => {
                if self.current_baseline.is_none() {
                    self.push_message("no baseline set — run 'baseline <proc>' first".into());
                    return;
                }

                let baseline_blocks = self.current_baseline.as_ref().unwrap().blocks.clone();
                let proc_name = _proc.to_string();
                let query = "scan".to_string();
                let mode = "-h".to_string();

                let tx = self.tx.clone();
                std::thread::spawn(move || {
                    let parts_ref: Vec<&str> = vec![&query, &proc_name, &mode];
                    match commands::scan(parts_ref) {
                        Ok(result) => {
                            tx.send(AppEvent::DiffResult(baseline_blocks, result)).ok();
                        }
                        Err(e) => {
                            tx.send(AppEvent::Output(Line::from(Span::styled(
                                format!("error: {}", e),
                                Style::default().fg(Color::Red),
                            ))))
                            .ok();
                        }
                    };
                });
            }
            ["clearbaseline"] => {
                self.current_baseline = None;
            }
            ["watch", _proc, _mode] => {
                let proc = _proc.to_string();
                let mode = _mode.to_string();
                let tx = self.tx.clone();

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

                        tx.send(AppEvent::RunCommand(cmd.clone())).ok();

                        std::thread::sleep(std::time::Duration::from_secs(2));
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
            }
            ["leak-m", _proc, _secs, _samples] => {
                let proc_name = _proc.to_string();
                let secs = _secs.to_string();
                let samples = _samples.to_string();
                let tx = self.tx.clone();

                self.push_message(format!("starting leak-m for {}...", proc_name));

                std::thread::spawn(move || {
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
                                Style::default().fg(Color::Red),
                            ))))
                            .ok();
                        }
                    });

                    while let Ok(line) = line_rx.recv() {
                        tx.send(AppEvent::Output(line)).ok();
                    }
                });
            }
            ["leak", _proc, _secs] => {
                let proc_name = _proc.to_string();
                let parts_owned: Vec<String> = parts.iter().map(|s| s.to_string()).collect();
                let tx = self.tx.clone();
                self.is_loading = true;
                self.loading_msg = format!("scanning leak for {}...", proc_name);
                std::thread::spawn(move || {
                    let parts_ref: Vec<&str> = parts_owned.iter().map(|s| s.as_str()).collect();
                    match commands::leak(parts_ref) {
                        Ok(result) => {
                            for line in result.0 {
                                tx.send(AppEvent::Output(line)).ok();
                            }
                            tx.send(AppEvent::LeakResult(result.1)).ok();
                        }
                        Err(e) => {
                            tx.send(AppEvent::Output(Line::raw(format!("{}", e)))).ok();
                        }
                    };
                });
            }
            ["scan", _proc, "-h"] | ["scan", _proc, "-h", "-g"] => {
                let proc_name = _proc.to_string();
                let parts_owned: Vec<String> = parts.iter().map(|s| s.to_string()).collect();
                let tx = self.tx.clone();
                self.is_loading = true;
                self.loading_msg = format!("scanning heap for {}...", proc_name);
                self.push_message(self.loading_msg.clone());

                std::thread::spawn(move || {
                    let parts_ref: Vec<&str> = parts_owned.iter().map(|s| s.as_str()).collect();
                    match commands::scan(parts_ref) {
                        Ok(result) => tx.send(AppEvent::ScanResult(result)).ok(),
                        Err(e) => tx.send(AppEvent::ScanError(e)).ok(),
                    };
                });
            }
            ["scan", _proc, "-a"] | ["scan", _proc, "-v"] => {
                let parts_owned: Vec<String> = parts.iter().map(|s| s.to_string()).collect();
                let tx = self.tx.clone();
                self.push_message(format!("scanning {}...", _proc));

                std::thread::spawn(move || {
                    let parts_ref: Vec<&str> = parts_owned.iter().map(|s| s.as_str()).collect();
                    match commands::scan(parts_ref) {
                        Ok(result) => tx.send(AppEvent::ScanResult(result)).ok(),
                        Err(e) => tx.send(AppEvent::ScanError(e)).ok(),
                    };
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
            ["clear"] => self.clear_output(),
            ["help"] => {
                self.push_message("commands:".into());
                self.push_message("  scan   <proc> -a          memory map".into());
                self.push_message("  scan   <proc> -h          heap stats".into());
                self.push_message("  scan   <proc> -v          loaded dlls".into());
                self.push_message("  leak   <proc> secs        detect leaks".into());
                self.push_message("  leak-m <proc> secs samp   detect leaks-samples".into());
                self.push_message(
                    "  watch  <proc> -flag       watch processes indefinitely".into(),
                );
                self.push_message(
                    "  stopwatch                 stop the current watch process".into(),
                );
                self.push_message("  list                      list processes".into());
                self.push_message("  clear                     clear output history".into());
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
                            "baseline : {} blocks ({} KB)",
                            baseline_blocks.iter().filter(|b| !b.is_free).count(),
                            baseline_total / 1024,
                        )));
                        self.push_line(Line::raw(format!(
                            "current  : {} blocks ({} KB)",
                            current.blocks.iter().filter(|b| !b.is_free).count(),
                            current_total / 1024,
                        )));
                        self.push_line(Line::raw("─".repeat(40)));

                        // new blocks
                        self.push_line(Line::from(Span::styled(
                            format!(
                                "+{} new blocks (+{} KB)",
                                new_blocks.len(),
                                new_bytes / 1024
                            ),
                            Style::default().fg(Color::Green),
                        )));
                        for block in new_blocks.iter().take(5) {
                            self.push_line(Line::from(Span::styled(
                                format!("  + 0x{:x}  {} KB", block.address, block.size / 1024),
                                Style::default().fg(Color::Green),
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
                                "-{} removed (-{} KB)",
                                removed_blocks.len(),
                                removed_bytes / 1024
                            ),
                            Style::default().fg(Color::Red),
                        )));

                        // net growth
                        let net_color = if net > 0 { Color::Red } else { Color::Green };
                        let net_sign = if net > 0 { "+" } else { "" };
                        self.push_line(Line::from(Span::styled(
                            format!("net growth: {}{} KB", net_sign, net / 1024),
                            Style::default().fg(net_color),
                        )));

                        // verdict
                        let verdict = if net > 1024 * 1024 {
                            ("LEAK CONFIRMED — significant growth", Color::Red)
                        } else if net > 0 {
                            ("growth detected — monitor over time", Color::Yellow)
                        } else {
                            ("no growth — heap stable", Color::Green)
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
                        });

                        if self.heap_history.len() > 4 {
                            self.heap_history.remove(0);
                        }
                    }
                    AppEvent::ScanError(e) => {
                        self.is_loading = false;
                        self.push_message(format!("error: {}", e));
                    }
                    AppEvent::Output(line) => {
                        self.push_line(line);
                    }
                    AppEvent::RunCommand(command) => {
                        self.dispatch(&command);
                    }
                    AppEvent::LeakResult(delta) => {
                        self.is_loading = false;
                        self.leak_deltas.push(delta);
                        if self.leak_deltas.len() > 30 {
                            self.leak_deltas.remove(0);
                        }
                    }
                }
            }

            terminal.draw(|frame| self.render(frame))?;

            if crossterm::event::poll(std::time::Duration::from_millis(100))? {
                if let Some(key) = event::read()?.as_key_press_event() {
                    match self.input_mode {
                        InputMode::Normal => match key.code {
                            KeyCode::Char('e') => self.input_mode = InputMode::Editing,
                            KeyCode::Char('q') => return Ok(()),
                            KeyCode::Up => self.scroll_up(),
                            KeyCode::Down => self.scroll_down(),
                            KeyCode::Tab => {
                                self.heap_view_mode = match self.heap_view_mode {
                                    HeapViewMode::Metrics => HeapViewMode::Allocations,
                                    HeapViewMode::Allocations => HeapViewMode::Chart,
                                    HeapViewMode::Chart => HeapViewMode::Metrics,
                                };
                            }
                            //page through table
                            KeyCode::Char(']') => self.next_page(),
                            KeyCode::Char('[') => self.prev_page(),
                            //row selection between page
                            KeyCode::Char('j') => self.select_next_row(),
                            KeyCode::Char('k') => self.select_prev_row(),
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
    }

    fn render(&mut self, frame: &mut Frame) {
        let outerlayout =
            Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
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
        let messages_area = layout[2];
        let footer = layout[3];

        self.messages_height = messages_area.height.saturating_sub(2);

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
        let help_message = Paragraph::new(text);
        frame.render_widget(help_message, help_area);

        let input = Paragraph::new(self.input.as_str())
            .style(match self.input_mode {
                InputMode::Normal => Style::default(),
                InputMode::Editing => Style::default().fg(Color::Yellow),
            })
            .block(Block::bordered().title("MVIS CLI"));
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
            .block(Block::bordered().title("Output (↑/↓ to scroll)"))
            .scroll((self.scroll_offset, 0))
            .wrap(Wrap { trim: false });

        frame.render_widget(messages_widget, messages_area);

        let proc_info = match &self.current_proc {
            Some(name) => format!(
                "Process : {}\nPID     : {}\nMemory  : {} MB",
                name,
                self.current_pid.unwrap_or(0),
                self.current_memory_mb.unwrap_or(0),
            ),
            None => "No process scanned yet.\nRun: scan <proc> -a".to_string(),
        };

        frame.render_widget(
            Paragraph::new(proc_info).block(
                Block::new()
                    .borders(Borders::ALL)
                    .fg(Color::Cyan)
                    .title("Process Info"),
            ),
            processlayout[0],
        );

        let args = vec![""];
        let mut proc_list: Vec<String> = vec![];
        match commands::list_processes(args) {
            Ok(procs) => {
                for p in procs {
                    proc_list.push(p);
                }
            }
            Err(e) => self.push_message(format!("Error: {e}")),
        };
        let proc_lines: Vec<Line> = proc_list.into_iter().map(Line::from).collect();

        frame.render_widget(
            Paragraph::new(proc_lines)
                .block(Block::new().borders(Borders::ALL).title("Process List"))
                .fg(Color::Cyan),
            processlayout[1],
        );

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
                            Style::default().fg(Color::DarkGray),
                        )),
                        Line::raw("  Need 2+ leak scans to plot."),
                        Line::raw("  Run: watch <proc> -l"),
                    ])
                    .block(
                        Block::bordered()
                            .title("Leak Delta [Tab for metrics]")
                            .fg(Color::Green),
                    ),
                    innerlayout[1],
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
                    Color::Red
                } else {
                    Color::Green
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
                        DiagnosticSeverity::LeakSuspected => Color::Red,
                        DiagnosticSeverity::Reclaimed => Color::Blue,
                        DiagnosticSeverity::Healthy => Color::Green,
                    };
                    let panel_w = innerlayout[1].width as usize;
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
                        .block(Block::bordered().title(title).fg(Color::Green))
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
                    innerlayout[1],
                );
            }
        } else {
            let heap_lines = match &self.heap_history.last() {
                None => vec![Line::raw("No heap data."), Line::raw("Run: scan <proc> -h")],
                Some(snap) => {
                    let panel_height = innerlayout[1].height as usize;
                    self.alloc_table_page_size = panel_height.saturating_sub(6);
                    let w = innerlayout[1].width as usize;

                    match self.heap_view_mode {
                        HeapViewMode::Metrics => render_heap_metrics(snap, w),
                        HeapViewMode::Allocations => render_alloc_table(
                            snap,
                            self.alloc_table_page,
                            self.alloc_table_page_size,
                            self.alloc_table_selected,
                        ),
                        HeapViewMode::Chart => unreachable!(),
                    }
                }
            };

            frame.render_widget(
                Paragraph::new(heap_lines).block(
                    Block::bordered()
                        .title(match self.heap_view_mode {
                            HeapViewMode::Metrics => "Heap View [Tab for table]",
                            HeapViewMode::Allocations => "Heap View [Tab for metrics]",
                            HeapViewMode::Chart => unreachable!(),
                        })
                        .fg(Color::Green),
                ),
                innerlayout[1],
            );
        }

        let footer_text = match self.input_mode {
            InputMode::Normal => Line::from(vec![
                Span::styled(
                    " NORMAL ",
                    Style::default().fg(Color::Black).bg(Color::Green),
                ),
                Span::raw("  press "),
                Span::styled(
                    "e",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" to type a command  •  "),
                Span::styled(
                    "q",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" to quit  •  "),
                Span::styled(
                    "tab",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" toggle heap view  •  "),
                Span::styled(
                    "↑↓",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" scroll output  •  "),
                Span::styled(
                    "[/]",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" prev/next page"),
            ]),
            InputMode::Editing => Line::from(vec![
                Span::styled(
                    " INSERT ",
                    Style::default().fg(Color::Black).bg(Color::Yellow),
                ),
                Span::raw("  try: "),
                Span::styled("scan notepad.exe -a", Style::default().fg(Color::Cyan)),
                Span::raw("  •  "),
                Span::styled("scan notepad.exe -h", Style::default().fg(Color::Cyan)),
                Span::raw("  •  "),
                Span::styled("leak notepad.exe 10", Style::default().fg(Color::Cyan)),
                Span::raw("  •  "),
                Span::styled("list", Style::default().fg(Color::Cyan)),
                Span::raw("  •  "),
                Span::styled(
                    "Esc",
                    Style::default()
                        .fg(Color::Yellow)
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
    }
}

fn render_heap_metrics(snap: &HeapSnapshot, width: usize) -> Vec<Line<'static>> {
    let mut lines = vec![];
    let bar_w = (width as usize).saturating_sub(20);

    // fragmentation bar
    let frag_fill = ((snap.fragmentation / 100.0) * bar_w as f64) as usize;
    let frag_color = if snap.fragmentation > 50.0 {
        Color::Red
    } else if snap.fragmentation > 25.0 {
        Color::Yellow
    } else {
        Color::Green
    };

    lines.push(Line::raw("── High-Level Metrics ──────────────────"));
    lines.push(Line::from(vec![
        Span::raw(format!("Frag  {:.1}%  ", snap.fragmentation)),
        Span::styled("█".repeat(frag_fill), Style::default().fg(frag_color)),
        Span::styled(
            "░".repeat(bar_w - frag_fill),
            Style::default().fg(Color::DarkGray),
        ),
    ]));

    // used/free bar
    let total = snap.used_bytes + snap.free_bytes;
    let used_fill = ((snap.used_bytes as f64 / total as f64) * bar_w as f64) as usize;
    lines.push(Line::from(vec![
        Span::raw("Used          "),
        Span::styled("█".repeat(used_fill), Style::default().fg(Color::Magenta)),
        Span::styled(
            "░".repeat(bar_w - used_fill),
            Style::default().fg(Color::DarkGray),
        ),
        Span::raw(format!("  {}", format_size(snap.used_bytes))),
    ]));
    lines.push(Line::from(vec![
        Span::raw("Free          "),
        Span::styled(
            "█".repeat(bar_w - used_fill),
            Style::default().fg(Color::Blue),
        ),
        Span::styled("░".repeat(used_fill), Style::default().fg(Color::DarkGray)),
        Span::raw(format!("  {}", format_size(snap.free_bytes))),
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
        format_size(snap.largest_used)
    )));
    lines.push(Line::raw(format!(
        "Largest free : {}",
        format_size(snap.largest_free)
    )));
    lines.push(Line::raw(""));

    let (msg, color) = if snap.fragmentation > 50.0 {
        ("⚠ High fragmentation", Color::Red)
    } else if snap.fragmentation > 25.0 {
        ("~ Moderate fragmentation", Color::Yellow)
    } else {
        ("✓ Heap healthy", Color::Green)
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
) -> Vec<Line<'static>> {
    let mut lines = vec![];

    let used_blocks: Vec<_> = {
        let mut b: Vec<_> = snap.blocks.iter().filter(|b| !b.is_free).collect();
        b.sort_by(|a, b| b.size.cmp(&a.size)); // largest first
        b
    };

    let total_pages = (used_blocks.len() + page_size - 1) / page_size;
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
            Style::default().bg(Color::DarkGray).fg(Color::White)
        } else if block.vm_protect == RegionProtect::Execute {
            Style::default().fg(Color::Red)
        } else if block.size >= 1024 * 1024 {
            Style::default().fg(Color::Red)
        } else if block.size >= 65536 {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        };

        lines.push(Line::from(Span::styled(
            format!(
                "{:<5} {:<18} {:<12} {:<8} {:<6} {}",
                idx,
                format!("0x{:x}", block.address),
                format_size(block.size),
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

#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ─────────────────────────────────────────────────────────────

    fn make_app() -> App {
        App::new()
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
            pointer_blocks: std::collections::HashSet::new(),
            referenced_blocks: std::collections::HashSet::new(),
        });
        app
    }

    #[test]
    fn clear_command_removes_output_and_resets_scroll() {
        let mut app = App::new();
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
        let mut app = App::new();

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
}
