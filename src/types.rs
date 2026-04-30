use serde::Serialize;

/// A single memory region in a process's address space.
/// 
/// Corresponds to one entry from `VirtualQueryEx` on Windows
/// or one line from `/proc/<pid>/maps` on Linux.
#[derive(Clone, Debug, Serialize)]
pub struct Region {
    pub base:    usize,
    pub size:    usize,
    pub state:   RegionState,
    pub kind:    RegionKind,
    pub protect: RegionProtect,
    pub name: String,
}

#[derive(Serialize)]
pub struct RegionEntry {
    pub base:    usize,
    pub size:    usize,
    pub state:   RegionState,
    pub kind:    RegionKind,
    pub protect: RegionProtect,
    pub name:    String,
    pub label:   String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub enum RegionState { Committed, Reserved, Free }

#[derive(Clone, Debug, PartialEq, Serialize)]
pub enum RegionKind { Image, Mapped, Private, Unknown }

#[derive(Clone, Debug, PartialEq, Serialize)]
pub enum RegionProtect { NoAccess, Readonly, ReadWrite, Execute, Guard, Other }

#[derive(Clone, Debug, Serialize)]
pub struct HeapBlock {
    pub address: usize,
    pub size:    usize,
    pub is_free: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct HeapStats {
    pub address: usize,
    pub size:    usize,
    pub rss:     usize,  // resident set size — actually in RAM
}