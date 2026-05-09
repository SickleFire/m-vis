# Changelog

## [0.2.0] - 2026-05-09
### Added
- Basic TUI with Process List and Heap View
- mvis tui (command)
  
### Known Issues
- TUI leak and other commands missing

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
