use strsim::jaro_winkler;
use sysinfo::System;

/// Minimum Jaro-Winkler similarity for a process name to be considered a match.
const SIMILARITY_THRESHOLD: f64 = 0.8;

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
}
