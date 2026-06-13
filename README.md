# mvis 

[![Tests](https://github.com/SickleFire/m-vis/actions/workflows/tests.yml/badge.svg)](https://github.com/SickleFire/m-vis/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

mvis: Memory debugging for developers who just want answers.
Simple. Fast. Works everywhere.

## Why mvis?

Existing tools are either platform-specific (Valgrind, WinDbg) or 
too complex for quick diagnostics. mvis gives you memory insights 
with a single command on any platform.

Our design philosophy is built around simplicity and accessibility because **We believe memory debugging should be accessible, not a PhD requirement.**

**"One command. All platforms. No configuration hell."**

## Status
Early but functional. Core scanning and leak detection work on both platforms. See the roadmap below for what's coming.

### New TUI
<img width="1919" height="986" alt="Screenshot 2026-06-05 173344" src="https://github.com/user-attachments/assets/31d98a81-a951-486c-a51e-9abc7b198406" />

<img width="1919" height="980" alt="Screenshot 2026-06-05 173607" src="https://github.com/user-attachments/assets/fea2c2f9-8f5d-48fb-b13f-21b6b30656e3" />

---

##  Features
-  **Process Scanning**: Inspect memory allocations of active processes.
-  **Heap-Level Analysis**: Dive into heap structures for detailed debugging.
-  **DLL Tracking**: Monitor and list all DLLs loaded by a target.
-  **Memory Leak Detection**: Identify and monitor processes with growing, unreleased allocations.
-  **Leak Delta Chart**: mvis includes a real-time leak delta chart that visualizes memory allocation trends over time directly in the TUI.
-  **Supported OS**: Windows, Linux, macOS

## macOS Code Signing

On macOS, `mvis` requires the `com.apple.security.cs.debugger` entitlement to inspect other processes due to Hardened Runtime restrictions. Even with `sudo`, inspecting third-party apps requires this entitlement.

To build and run `mvis` on macOS:
```bash
# We provide a Makefile that automatically builds and signs the binary ad-hoc
make build

# To run a scan using the Makefile helper:
make run-scan PROCESS=language_server_macos_arm MODE=-a
```
*Note: Apple platform apps (Safari, Finder) and some Hardened Runtime apps (WhatsApp) will remain protected by System Integrity Protection (SIP) even with this entitlement.*

## Usage
```powershell
# visualize memory map
mvis scan notepad.exe -a

# heap stats
mvis scan notepad.exe -h

# detect leaks
mvis leak notepad.exe 10

# multi-sample leak detection
mvis leak-m notepad.exe 10 3

# list processes
mvis list

#open mvis tui
mvis tui
```
### Examples
```powershell
mvis leak leaking_app.exe 10
```
Output: <br>
<img width="570" height="77" alt="Screenshot 2026-05-01 181525" src="https://github.com/user-attachments/assets/fbef4565-45b3-4388-8c6a-85f8d0df89f5" /> <br>

```powershell
mvis scan myapp.exe -a
```
<br>
Output: <br>
<img width="579" height="133" alt="Screenshot 2026-05-01 182001" src="https://github.com/user-attachments/assets/f9bd515e-9cc7-49f8-8cf5-9d2e79ab8f22" />
. <br>
. <br>
. <br>
<img width="1091" height="267" alt="Screenshot 2026-05-01 181929" src="https://github.com/user-attachments/assets/52563bf0-7b6b-4875-8eb1-ed692622aed5" />

---

## Installation

### From GitHub Releases (Recommended)
Download pre-built binaries from [Releases](https://github.com/SickleFire/m-vis/releases):
- **Windows:** `mvis-windows-x86_64.exe`
- **Linux:** `mvis-linux-x86_64`


### From source
```bash
git clone https://github.com/SickleFire/m-vis
cd mvis
cargo build --release
```

## Testing

The project includes comprehensive unit and integration tests to ensure reliability across platforms.

### Run all tests
```bash
cargo test
```

### Run only integration tests
```bash
cargo test --test integration_tests
```

### Run integration tests with admin privileges (advanced)
```bash
# On Linux with sudo
sudo cargo test --test integration_tests -- --include-ignored

# On Windows (run terminal as Administrator)
cargo test --test integration_tests -- --include-ignored
```
---
### Roadmap
See [Roadmap](https://github.com/SickleFire/m-vis/issues/24) 

## License

MIT — see [LICENSE](LICENSE.md)
