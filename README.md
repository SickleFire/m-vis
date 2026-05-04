# mvis 

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

---

##  Features
-  **Process Scanning**: Inspect memory allocations of active processes.
-  **Heap-Level Analysis**: Dive into heap structures for detailed debugging.
-  **DLL Tracking**: Monitor and list all DLLs loaded by a target.
-  **Memory Leak Detection**: Identify and monitor processes with growing, unreleased allocations.
-  **Stack Tracing**: Capture call stacks to pinpoint allocation sources and trace execution paths.
-  **Supported OS**: Windows, Linux

## Known Limitations
- ptrace leak tracing requires sudo or ptrace_scope=0
- macOS not supported yet

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

### From source
```bash
git clone https://github.com/SickleFire/m-vis
cd mvis
cargo build --release
```

### Roadmap
- [ ] TUI frontend for heap analysis (Changed to TUI instead of GUI following our design philosophy of being lightweight)
- [ ] Heap fragmentation visualization
- [ ] Realtime heap scanning
- [ ] Cross Platform support for MacOS
- [ ] Performance improvements
- [x] Stack trace support for windows
- [x] Json exports

### Known Issues
- [ ] Heap walking is slow
- [ ] Missing stack trace for windows
- [ ] Linux stack frames resolve to addresses, not function names yet
- [ ] Missing Tests

## License

MIT — see [LICENSE](LICENSE.md)
