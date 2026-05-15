# Changelog
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
