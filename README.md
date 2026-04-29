# Mvis 
**Memory Visualizer Debugger Tool**

mvis is a lightweight cross-platform debugging utility designed to **scan and visualize process memory allocation**, down to the **heap level**. It helps developers and systems programmers gain deep insights into how memory is being used by running processes.

## Why mvis?

Existing tools are either platform-specific (Valgrind, WinDbg) or 
too complex for quick diagnostics. mvis gives you memory insights 
with a single command on any platform.

---

##  Features
-  **Process Scanning**: Inspect memory allocations of active processes.
-  **Heap-Level Analysis**: Dive into heap structures for detailed debugging.
-  **DLL Tracking**: Monitor and list all DLLs loaded by a target.
-  **Memory Leak Detection**: Identify and monitor processes with growing, unreleased allocations.
-  **Stack Tracing**: Capture call stacks to pinpoint allocation sources and trace execution paths. (Linux)
-  **Supported OS**: Windows, Linux

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
- [ ] Stack traces support for windows
- [x] Json exports

## License

MIT — see [LICENSE](LICENSE.md)
