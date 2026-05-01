# Contributing to mvis

Thanks for your interest in contributing! mvis is an early-stage project and contributions of all kinds are welcome — bug reports, fixes, new features, documentation, and platform testing.

## Ways to Contribute

- **Bug reports** — found something broken? Open an issue with steps to reproduce
- **Platform testing** — test on different OS versions and report results
- **New features** — check the roadmap in README for planned features
- **Documentation** — improve docs, add examples, fix typos
- **Performance** — the heap walker is slow on large processes, improvements welcome

## Getting Started

### Prerequisites
- Rust (latest stable)
- Windows 10/11 for Windows features
- Linux or WSL for Linux features

### Build from source
```bash
git clone https://github.com/SickleFire/m-vis
cd m-vis
cargo build
```

### Run tests
```bash
cargo test
```

---

## Pull Request Guidelines

- One feature or fix per PR — keep changes focused
- Test on the platform your change affects
- Add documentation comments (`///`) to any public functions you add
- Describe what your PR does and why in the description

---

## Reporting Bugs

Open a GitHub issue with:

- Your OS and version
- The command you ran
- What you expected vs what happened
- Any error messages or panics

---

*mvis is MIT licensed. By contributing you agree your changes will be released under the same license.*


