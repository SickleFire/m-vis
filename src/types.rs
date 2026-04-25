
#[derive(Clone, Debug)]
pub struct Region {
    pub base:    usize,
    pub size:    usize,
    pub state:   RegionState,
    pub kind:    RegionKind,
    pub protect: RegionProtect,
}

#[derive(Clone, Debug, PartialEq)]
pub enum RegionState { Committed, Reserved, Free }

#[derive(Clone, Debug, PartialEq)]
pub enum RegionKind { Image, Mapped, Private, Unknown }

#[derive(Clone, Debug, PartialEq)]
pub enum RegionProtect { NoAccess, Readonly, ReadWrite, Execute, Guard, Other }

#[derive(Clone, Debug)]
pub struct HeapBlock {
    pub address: usize,
    pub size:    usize,
    pub is_free: bool,
}