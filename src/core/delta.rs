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
        let allocated_kb = self.allocated_bytes / 1024;
        let freed_kb = self.freed_bytes / 1024;
        let net_kb = net.abs() / 1024;

        if net > 0 {
            (
                format!("Positive Allocation: +{} KB (Allocated: {} KB | Freed: {} KB) -> Leak Suspected!", net_kb, allocated_kb, freed_kb),
                DiagnosticSeverity::LeakSuspected
            )
        } else if net < 0 {
            (
                format!("Negative Allocation: -{} KB (Allocated: {} KB | Freed: {} KB) -> Memory Reclaimed.", net_kb, allocated_kb, freed_kb),
                DiagnosticSeverity::Reclaimed
            )
        } else {
            (
                format!("Balanced Allocation: 0 KB Change (Allocated: {} KB | Freed: {} KB) -> Healthy.", allocated_kb, freed_kb),
                DiagnosticSeverity::Healthy
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