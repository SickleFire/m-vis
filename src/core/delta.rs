use crate::utils::formatting::format_bytes;

#[derive(Debug, Clone)]
pub struct LeakDelta {
    pub freed_bytes: usize,
    pub allocated_bytes: usize,
}

impl LeakDelta {
    /// Computes the net change.
    /// Positive means accumulation (leak), negative means memory is being drained.
    pub fn net_change(&self) -> isize {
        self.allocated_bytes as isize - self.freed_bytes as isize
    }

    /// Generates the single line of truth requested for the TUI/CLI
    pub fn get_diagnostic_line(&self) -> (String, DiagnosticSeverity) {
        let net = self.net_change();
        let allocated_kb = format_bytes(self.allocated_bytes as u64);
        let freed_kb = format_bytes(self.freed_bytes as u64);
        let net_kb = format_bytes(net.abs() as u64);

        if net > 0 {
            (
                format!(
                    "Positive Allocation: +{} (Allocated: {} | Freed: {} ) -> Leak Suspected!",
                    net_kb, allocated_kb, freed_kb
                ),
                DiagnosticSeverity::LeakSuspected,
            )
        } else if net < 0 {
            (
                format!(
                    "Negative Allocation: -{} (Allocated: {} | Freed: {}) -> Memory Reclaimed.",
                    net_kb, allocated_kb, freed_kb
                ),
                DiagnosticSeverity::Reclaimed,
            )
        } else {
            (
                format!(
                    "Balanced Allocation: 0 KB Change (Allocated: {} | Freed: {}) -> Healthy.",
                    allocated_kb, freed_kb
                ),
                DiagnosticSeverity::Healthy,
            )
        }
    }
}

#[derive(Debug, Clone)]
pub enum DiagnosticSeverity {
    Healthy,
    Reclaimed,
    LeakSuspected,
}
