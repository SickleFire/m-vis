use serde::{Deserialize, Serialize};

/// A single memory region in a process's address space.
///
/// Corresponds to one entry from `VirtualQueryEx` on Windows
/// or one line from `/proc/<pid>/maps` on Linux.
#[derive(Clone, Debug, Serialize)]
pub struct Region {
    pub base: usize,
    pub size: usize,
    pub state: RegionState,
    pub kind: RegionKind,
    pub protect: RegionProtect,
    pub name: String,
}

#[derive(Serialize)]
pub struct RegionEntry {
    pub base: usize,
    pub size: usize,
    pub state: RegionState,
    pub kind: RegionKind,
    pub protect: RegionProtect,
    pub name: String,
    pub label: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub enum RegionState {
    Committed,
    Reserved,
    Free,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub enum RegionKind {
    Image,
    Mapped,
    Private,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum RegionProtect {
    NoAccess,
    Readonly,
    ReadWrite,
    Execute,
    Guard,
    Other,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HeapBlock {
    pub address: usize,
    pub size: usize,
    pub is_free: bool,
    pub vm_protect: RegionProtect,
}

#[derive(Clone, Debug, Serialize)]
pub struct HeapStats {
    pub address: usize,
    pub size: usize,
    pub rss: usize, // resident set size — actually in RAM
}

#[derive(Debug, Clone, PartialEq)]
pub enum ModuleStatus {
    Ok,
    Tampered,
    Injected,
    Unreadable,
    Modified,
}

#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub base: usize,
    pub size: usize,
    pub name: String,
    pub path: String,
    pub status: ModuleStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PointerEdge {
    pub target: usize,
    pub target_is_free: bool,
    /// Exact pointer value read from the source block.
    #[serde(default)]
    pub pointer_value: usize,
    /// Address of the pointer slot in the source block.
    #[serde(default)]
    pub source_address: usize,
    /// A process stack sampled while the edge was observed, not its allocation provenance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_stack: Option<crate::core::stack_trace::StackTrace>,
    /// Why `observed_stack` could not be captured, if unwinding was unavailable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stack_trace_error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::PointerEdge;

    #[test]
    fn pointer_edge_deserializes_legacy_data_without_trace_fields() {
        let edge: PointerEdge =
            serde_json::from_str(r#"{"target":8192,"target_is_free":true}"#).unwrap();
        assert_eq!(edge.pointer_value, 0);
        assert_eq!(edge.source_address, 0);
        assert!(edge.observed_stack.is_none());
        assert!(edge.stack_trace_error.is_none());
    }

    #[test]
    fn pointer_edge_serializes_observed_stack_and_omits_empty_metadata() {
        let edge = PointerEdge {
            target: 8192,
            target_is_free: true,
            pointer_value: 8200,
            source_address: 4096,
            observed_stack: Some(crate::core::stack_trace::StackTrace {
                pid: 42,
                frames: vec![crate::core::stack_trace::StackFrame {
                    instruction_pointer: 0x1234,
                    base_pointer: 0,
                    return_address: 0,
                    symbol: "observed_function".into(),
                }],
                symbol_warning: None,
            }),
            stack_trace_error: None,
        };
        let json = serde_json::to_value(edge).unwrap();

        assert_eq!(json["observed_stack"]["pid"], 42);
        assert_eq!(
            json["observed_stack"]["frames"][0]["symbol"],
            "observed_function"
        );
        assert!(json.get("stack_trace_error").is_none());
    }
}
