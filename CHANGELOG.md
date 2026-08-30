# Changelog
## [0.6.0-rc1] - 2026-08-30
### Added
- **Reference Pointer Tree** (Linux and Windows)
- **Hex Dump View** 

### Fixed
- **Pointer references now available for Linux**


## [0.5.0] - 2026-07-30
### Added
- added **CI/CD commands**: `--warmup` `--growth-rate` `--sample-interval` `--diff-only`
- added **diff file support** and save to TUI/CLI
- added **allocation histogram**
- QOL added **settings menu**
- QOL made **heap/output swappable**
- **CI/CD Mode**: Full programmatic integration layer with JSON/CSV export, differential leak detection (`--diff-only`), configurable sampling, and growth rate monitoring.
- **Enhanced TUI**: keyboard-driven process selection, quick action buttons.
- **Improved Leak Detection**: Better Linux heap walk via /proc/maps, optimized memory diff algorithms for large heaps.

### Fixed
- Fix macOS smoke test timeout by using sudo
- implement walk_heap_granular for linux
- Fix #86: Add configurable iteration limits to walk_regions
- Improved Junit export with refactors
- made process list and tree scrollable
- fix: fail loudly on binary download errors in smoke-test action

## [0.5.0-rc2] - 2026-07-25
### Added
- added CI/CD commands: `--warmup` `--growth-rate` `--sample-interval` `--diff-only`
- added diff file support and save to TUI/CLI
- added **allocation histogram**
- QOL added **settings menu**
- QOL made **heap/output swappable**

### Fixed
- Fix macOS smoke test timeout by using sudo
- implement walk_heap_granular for linux
- Fix #86: Add configurable iteration limits to walk_regions
- Improved Junit export with refactors
- made process list and tree scrollable
- fix: fail loudly on binary download errors in smoke-test action

## [0.5.0-rc1] - 2026-07-6
### Added
- **CI/CD Mode**: Full programmatic integration layer with JSON/CSV export, differential leak detection (`--diff-only`), configurable sampling, and growth rate monitoring.
- **Enhanced TUI**: keyboard-driven process selection, quick action buttons.
- **Improved Leak Detection**: Better Linux heap walk via /proc/maps, optimized memory diff algorithms for large heaps.

## [0.4.0] - 2026-06-30
### Added
- Linux man pages (Makefile)
- Process Tree View

### Fixed
- Watch mode delay from 2 secs to 1 secs.
- Aligned heap high level metrics
- Net growth overflow (added i64)

## [0.4.0-rc1] - 2026-06-20
### Added
- MacOS support
- Leak Delta Chart
- Help Subcommand
- Criterion Benches
- (TUI) themes
- (TUI) diff commands
- (CLI) process name fuzzy matchable

## [0.3.0] - 2026-05-31
### Added
- (TUI) modules command
- (TUI) watch command

### Fixed
- (LINUX) hide worker threads from process list

### Known Issues
- [PTR] and [REF] tags can't account for memory rotations.
- no walk_heap_granular equivalent for linux

## [0.2.4] - 2026-05-21
### Added
- (CLI) modules command
- (TUI) [PTR] and [REF] tags in Heap view allocation table, issue #1

### Known Issues
- [PTR] and [REF] tags can't account for memory rotations.
- no modules command for linux
- no walk_heap_granular equivalent for linux

## [0.2.3] - 2026-05-15
### Added
- (TUI) clear command

### Fixed
- fixed issue #5 Linux - (warn when debug symbols are missing)

## [0.2.2] - 2026-05-13
### Added
- (TUI) protection / permissions on heap block in heap view alloc table

### Fixed
- fixed issue #2

## [0.2.1] - 2026-05-10
### Added
- leak command for tui
- leak-m command for tui

### Fixed
- fixed issue (scan app.exe -h has println in tui v0.2.0)
- fixed frag ratio to show fragmentation

## [0.2.0] - 2026-05-09
### Added
- Basic TUI with Process List and Heap View
- mvis tui (command)
  
### Known Issues
- TUI leak and other commands missing
- scan app.exe -h has println in tui

## [0.1.1] - 2026-05-05
### Added
- Integration test suite
- CI/CD pipeline with GitHub Actions
- Pre-built binary releases for Windows and Linux

### Fixed
- Replaced Heap Walking to ReadProcessMemory
- Process lookup now uses stable system processes
- JSON export validation improved (tests)

### Known Issues
- Linux symbol resolution inconsistent

## [0.1.0]
- Initial CLI release
- Windows and Linux memory scanning
- Leak detection
