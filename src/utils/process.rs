use strsim::jaro_winkler;
use sysinfo::System;

/// Minimum Jaro-Winkler similarity for a process name to be considered a match.
const SIMILARITY_THRESHOLD: f64 = 0.8;

#[derive(Debug, Clone)]
pub struct ProcessTreeNode {
    pub pid: u32,
    pub name: String,
    pub memory: u64,
    pub children: Vec<ProcessTreeNode>,
}

impl ProcessTreeNode {
    pub fn total_memory(&self) -> u64 {
        self.memory + self.children.iter().map(|c| c.total_memory()).sum::<u64>()
    }
}

/// Builds a process tree rooted at the given PID.
/// Finds the root ancestor first, then collects all descendants.
pub fn build_process_tree(pid: u32) -> Option<ProcessTreeNode> {
    let sys = System::new_all();
    let processes: &std::collections::HashMap<sysinfo::Pid, sysinfo::Process> = sys.processes();

    let target: &sysinfo::Process = processes
        .values()
        .find(|p| p.pid().as_u32() == pid)?;

    // Walk up to find the root ancestor
    let mut root_pid = pid;
    let mut visited = std::collections::HashSet::new();
    visited.insert(root_pid);
    loop {
        let proc = processes.values().find(|p| p.pid().as_u32() == root_pid)?;
        if let Some(parent_pid) = proc.parent() {
            let ppid = parent_pid.as_u32();
            if ppid == 0 || ppid == root_pid || visited.contains(&ppid) {
                break;
            }
            // Only go up if parent has the same name (same process group)
            if let Some(parent) = processes.values().find(|p| p.pid().as_u32() == ppid) {
                let parent_name = parent.name().to_string_lossy().to_string();
                let current_name = target.name().to_string_lossy().to_string();
                if parent_name == current_name {
                    root_pid = ppid;
                    visited.insert(root_pid);
                } else {
                    break;
                }
            } else {
                break;
            }
        } else {
            break;
        }
    }

    fn build_subtree(
        pid: u32,
        processes: &std::collections::HashMap<sysinfo::Pid, sysinfo::Process>,
    ) -> Option<ProcessTreeNode> {
        let proc_entry = processes.values().find(|p| p.pid().as_u32() == pid)?;
        let name = proc_entry.name().to_string_lossy().to_string();
        let memory = proc_entry.memory();

        let mut children: Vec<ProcessTreeNode> = processes
            .values()
            .filter(|p: &&sysinfo::Process| {
                p.parent()
                    .map(|pp| pp.as_u32() == pid)
                    .unwrap_or(false)
                    && p.pid().as_u32() != pid
                    && p.thread_kind().is_none()
            })
            .filter_map(|p: &sysinfo::Process| build_subtree(p.pid().as_u32(), processes))
            .collect();
        children.sort_by(|a, b| b.memory.cmp(&a.memory));

        Some(ProcessTreeNode {
            pid,
            name,
            memory,
            children,
        })
    }

    build_subtree(root_pid, processes)
}

#[derive(Debug, Clone)]
pub struct TreeDisplayRow {
    pub pid: u32,
    pub name: String,
    pub memory: u64,
    pub depth: usize,
    pub has_children: bool,
    pub is_collapsed: bool,
}

/// Flattens a process tree into display rows, respecting collapsed state.
pub fn flatten_tree(
    node: &ProcessTreeNode,
    depth: usize,
    collapsed: &std::collections::HashSet<u32>,
    rows: &mut Vec<TreeDisplayRow>,
) {
    let is_collapsed = collapsed.contains(&node.pid);
    rows.push(TreeDisplayRow {
        pid: node.pid,
        name: node.name.clone(),
        memory: node.memory,
        depth,
        has_children: !node.children.is_empty(),
        is_collapsed,
    });
    if !is_collapsed {
        for child in &node.children {
            flatten_tree(child, depth + 1, collapsed, rows);
        }
    }
}

/// Result of a fuzzy process-name lookup.
#[derive(Debug, PartialEq)]
pub enum FuzzyMatch {
    /// Exactly one process name matched — carries the PID.
    Found(u32),
    /// Multiple distinct process names scored above the threshold — carries
    /// (name, first_pid) pairs ordered by similarity score, highest first.
    Ambiguous(Vec<(String, u32)>),
    /// Nothing scored above the threshold.
    NotFound,
}

/// Matches `query` against `candidates` using an exact-then-fuzzy strategy.
///
/// Tries a case-insensitive exact match first. If that fails, computes the
/// Jaro-Winkler similarity between `query` and each candidate name and keeps
/// those at or above [`SIMILARITY_THRESHOLD`]. Results are deduplicated by
/// name, then sorted by similarity score descending so the best match appears
/// first when presenting an ambiguous list.
fn fuzzy_match(query: &str, candidates: &[(String, u32)]) -> FuzzyMatch {
    let query_lower = query.to_lowercase();

    // Exact match wins immediately.
    if let Some((_, pid)) = candidates
        .iter()
        .find(|(name, _)| name.to_lowercase() == query_lower)
    {
        return FuzzyMatch::Found(*pid);
    }

    // Fuzzy pass: score every unique name, keep those above threshold.
    let mut seen = std::collections::HashSet::new();
    let mut scored: Vec<(String, u32, f64)> = candidates
        .iter()
        .filter_map(|(name, pid)| {
            let score = jaro_winkler(&query_lower, &name.to_lowercase());
            if score >= SIMILARITY_THRESHOLD {
                Some((name.clone(), *pid, score))
            } else {
                None
            }
        })
        .filter(|(name, _, _)| seen.insert(name.to_lowercase()))
        .collect();

    // Best match first; alphabetical tiebreak for stable output.
    scored.sort_by(|a, b| {
        b.2.partial_cmp(&a.2)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });

    let unique: Vec<(String, u32)> = scored.into_iter().map(|(n, p, _)| (n, p)).collect();

    match unique.len() {
        0 => FuzzyMatch::NotFound,
        1 => FuzzyMatch::Found(unique[0].1),
        _ => FuzzyMatch::Ambiguous(unique),
    }
}

/// Resolves a process-name query to a PID by scanning the live process list.
pub fn fuzzy_find_pid(query: &str) -> FuzzyMatch {
    let sys = System::new_all();
    let candidates: Vec<(String, u32)> = sys
        .processes()
        .values()
        .map(|p| (p.name().to_string_lossy().to_string(), p.pid().as_u32()))
        .collect();
    fuzzy_match(query, &candidates)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(pairs: &[(&str, u32)]) -> Vec<(String, u32)> {
        pairs.iter().map(|(n, p)| (n.to_string(), *p)).collect()
    }

    #[test]
    fn exact_match_returns_found() {
        let candidates = c(&[("notepad.exe", 100), ("notes.exe", 200)]);
        assert_eq!(
            fuzzy_match("notepad.exe", &candidates),
            FuzzyMatch::Found(100)
        );
    }

    #[test]
    fn exact_match_is_case_insensitive() {
        let candidates = c(&[("Notepad.EXE", 100)]);
        assert_eq!(
            fuzzy_match("notepad.exe", &candidates),
            FuzzyMatch::Found(100)
        );
    }

    #[test]
    fn exact_match_takes_priority_over_fuzzy() {
        // "note.exe" should match exactly, not be treated as fuzzy input.
        let candidates = c(&[("note.exe", 100), ("notepad.exe", 200)]);
        assert_eq!(fuzzy_match("note.exe", &candidates), FuzzyMatch::Found(100));
    }

    #[test]
    fn fuzzy_matches_without_exe_extension() {
        // "notepad" is similar enough to "notepad.exe".
        let candidates = c(&[("notepad.exe", 100)]);
        assert_eq!(fuzzy_match("notepad", &candidates), FuzzyMatch::Found(100));
    }

    #[test]
    fn fuzzy_single_match_returns_found() {
        let candidates = c(&[("notepad.exe", 100), ("other.exe", 200)]);
        // "notepad" scores high vs "notepad.exe", low vs "other.exe".
        assert_eq!(fuzzy_match("notepad", &candidates), FuzzyMatch::Found(100));
    }

    #[test]
    fn fuzzy_tolerates_minor_typo() {
        // "notepd" is close enough to "notepad.exe".
        let candidates = c(&[("notepad.exe", 100)]);
        assert_eq!(fuzzy_match("notepd", &candidates), FuzzyMatch::Found(100));
    }

    #[test]
    fn multiple_distinct_matches_returns_ambiguous() {
        let candidates = c(&[("notepad.exe", 100), ("notes.exe", 200)]);
        let result = fuzzy_match("note", &candidates);
        assert!(
            matches!(result, FuzzyMatch::Ambiguous(_)),
            "expected Ambiguous, got {:?}",
            result
        );
        if let FuzzyMatch::Ambiguous(matches) = result {
            assert_eq!(matches.len(), 2);
        }
    }

    #[test]
    fn ambiguous_results_sorted_by_score_best_first() {
        // "notes" is closer to "notes.exe" than "notepad.exe", so it should appear first.
        let candidates = c(&[("notepad.exe", 100), ("notes.exe", 200)]);
        let result = fuzzy_match("notes", &candidates);
        if let FuzzyMatch::Ambiguous(matches) = result {
            assert_eq!(matches[0].0, "notes.exe");
        } else {
            panic!("expected Ambiguous, got {:?}", result);
        }
    }

    #[test]
    fn multiple_pids_same_name_returns_found_with_first_pid() {
        // Three chrome.exe instances deduplicate to one name; exact match returns first PID.
        let candidates = c(&[
            ("chrome.exe", 100),
            ("chrome.exe", 200),
            ("chrome.exe", 300),
        ]);
        assert_eq!(
            fuzzy_match("chrome.exe", &candidates),
            FuzzyMatch::Found(100)
        );
    }

    #[test]
    fn multiple_instances_same_name_fuzzy_returns_found() {
        let candidates = c(&[("chrome.exe", 100), ("chrome.exe", 200)]);
        assert_eq!(fuzzy_match("chrome", &candidates), FuzzyMatch::Found(100));
    }

    #[test]
    fn unrelated_name_returns_not_found() {
        let candidates = c(&[("notepad.exe", 100)]);
        assert_eq!(fuzzy_match("zzzzzz", &candidates), FuzzyMatch::NotFound);
    }

    #[test]
    fn empty_candidates_returns_not_found() {
        assert_eq!(fuzzy_match("anything", &[]), FuzzyMatch::NotFound);
    }

    fn make_tree() -> ProcessTreeNode {
        ProcessTreeNode {
            pid: 100,
            name: "chrome.exe".into(),
            memory: 200 * 1024 * 1024,
            children: vec![
                ProcessTreeNode {
                    pid: 101,
                    name: "chrome.exe".into(),
                    memory: 100 * 1024 * 1024,
                    children: vec![],
                },
                ProcessTreeNode {
                    pid: 102,
                    name: "chrome.exe".into(),
                    memory: 50 * 1024 * 1024,
                    children: vec![],
                },
            ],
        }
    }

    #[test]
    fn total_memory_sums_entire_tree() {
        let tree = make_tree();
        assert_eq!(tree.total_memory(), 350 * 1024 * 1024);
    }

    #[test]
    fn flatten_tree_produces_correct_depths() {
        let tree = make_tree();
        let mut rows = Vec::new();
        flatten_tree(&tree, 0, &std::collections::HashSet::new(), &mut rows);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].depth, 0);
        assert_eq!(rows[1].depth, 1);
        assert_eq!(rows[2].depth, 1);
    }

    #[test]
    fn flatten_tree_respects_collapsed() {
        let tree = make_tree();
        let mut collapsed = std::collections::HashSet::new();
        collapsed.insert(100u32);
        let mut rows = Vec::new();
        flatten_tree(&tree, 0, &collapsed, &mut rows);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].is_collapsed);
    }

    #[test]
    fn flatten_tree_leaf_has_no_children_flag() {
        let tree = make_tree();
        let mut rows = Vec::new();
        flatten_tree(&tree, 0, &std::collections::HashSet::new(), &mut rows);
        assert!(rows[0].has_children);
        assert!(!rows[1].has_children);
        assert!(!rows[2].has_children);
    }
}
