//! Differential testing framework.
//!
//! Compares outputs of two implementations against the same inputs
//! to detect discrepancies. Used to verify cross-implementation
//! compatibility (e.g., our FROST vs. reference FROST).

use std::collections::HashMap;

/// Result of a differential test comparison.
#[derive(Debug, Clone)]
pub struct DiffResult<T: Clone + PartialEq> {
    pub input_label: String,
    pub implementation_a: T,
    pub implementation_b: T,
    pub matches: bool,
}

/// Run a differential comparison between two functions over a set
/// of byte-vector inputs.
pub fn differential_test<A, B, T>(
    inputs: &[(String, Vec<u8>)],
    impl_a: A,
    impl_b: B,
) -> Vec<DiffResult<T>>
where
    A: Fn(&[u8]) -> T,
    B: Fn(&[u8]) -> T,
    T: Clone + PartialEq,
{
    inputs
        .iter()
        .map(|(label, input)| {
            let result_a = impl_a(input);
            let result_b = impl_b(input);
            DiffResult {
                input_label: label.clone(),
                matches: result_a == result_b,
                implementation_a: result_a,
                implementation_b: result_b,
            }
        })
        .collect()
}

/// Summary of a differential test run.
#[derive(Debug, Clone)]
pub struct DiffSummary {
    pub total: usize,
    pub matching: usize,
    pub mismatching: usize,
    pub mismatches: Vec<String>,
}

impl DiffSummary {
    pub fn from_results<T: Clone + PartialEq>(results: &[DiffResult<T>]) -> Self {
        let total = results.len();
        let matching = results.iter().filter(|r| r.matches).count();
        let mismatches: Vec<String> = results
            .iter()
            .filter(|r| !r.matches)
            .map(|r| r.input_label.clone())
            .collect();
        Self {
            total,
            matching,
            mismatching: total - matching,
            mismatches,
        }
    }

    pub fn all_match(&self) -> bool {
        self.mismatching == 0
    }

    pub fn match_rate(&self) -> f64 {
        if self.total == 0 {
            1.0
        } else {
            self.matching as f64 / self.total as f64
        }
    }
}

/// Compare hash function outputs for consistency.
pub fn compare_hashes(
    inputs: &[Vec<u8>],
    hash_a: impl Fn(&[u8]) -> Vec<u8>,
    hash_b: impl Fn(&[u8]) -> Vec<u8>,
) -> DiffSummary {
    let results: Vec<DiffResult<Vec<u8>>> = inputs
        .iter()
        .enumerate()
        .map(|(i, input)| {
            let ra = hash_a(input);
            let rb = hash_b(input);
            DiffResult {
                input_label: format!("input-{i}"),
                matches: ra == rb,
                implementation_a: ra,
                implementation_b: rb,
            }
        })
        .collect();
    DiffSummary::from_results(&results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_implementations() {
        let inputs: Vec<(String, Vec<u8>)> = vec![
            ("a".into(), vec![1, 2, 3]),
            ("b".into(), vec![4, 5, 6]),
        ];
        let results = differential_test(
            &inputs,
            |input: &[u8]| input.len(),
            |input: &[u8]| input.len(),
        );
        let summary = DiffSummary::from_results(&results);
        assert!(summary.all_match());
        assert_eq!(summary.match_rate(), 1.0);
    }

    #[test]
    fn mismatching_implementations() {
        let inputs: Vec<(String, Vec<u8>)> = vec![
            ("a".into(), vec![1]),
            ("b".into(), vec![2]),
        ];
        let results = differential_test(
            &inputs,
            |input: &[u8]| input[0] as u32 * 2,
            |input: &[u8]| input[0] as u32 * 3,
        );
        let summary = DiffSummary::from_results(&results);
        assert!(!summary.all_match());
        assert_eq!(summary.mismatching, 2);
    }

    #[test]
    fn empty_inputs() {
        let inputs: Vec<(String, Vec<u8>)> = vec![];
        let results = differential_test(
            &inputs,
            |_: &[u8]| 0u32,
            |_: &[u8]| 0u32,
        );
        let summary = DiffSummary::from_results(&results);
        assert_eq!(summary.total, 0);
        assert_eq!(summary.match_rate(), 1.0);
    }

    #[test]
    fn partial_match() {
        let inputs: Vec<(String, Vec<u8>)> = vec![
            ("a".into(), vec![0]),
            ("b".into(), vec![1]),
        ];
        let results = differential_test(
            &inputs,
            |input: &[u8]| input[0],
            |input: &[u8]| if input[0] == 0 { 0 } else { 99 },
        );
        let summary = DiffSummary::from_results(&results);
        assert_eq!(summary.matching, 1);
        assert_eq!(summary.mismatching, 1);
    }

    #[test]
    fn compare_hashes_identical() {
        let inputs = vec![vec![1, 2, 3], vec![4, 5, 6]];
        let summary = compare_hashes(&inputs, |d| vec![d.len() as u8], |d| vec![d.len() as u8]);
        assert!(summary.all_match());
    }

    #[test]
    fn compare_hashes_different() {
        let inputs = vec![vec![1, 2, 3]];
        let summary = compare_hashes(&inputs, |_| vec![1u8], |_| vec![2u8]);
        assert!(!summary.all_match());
    }

    #[test]
    fn mismatch_labels_recorded() {
        let inputs: Vec<(String, Vec<u8>)> = vec![
            ("first".into(), vec![1]),
            ("second".into(), vec![2]),
        ];
        let results = differential_test(
            &inputs,
            |input: &[u8]| input[0],
            |_: &[u8]| 99u8,
        );
        let summary = DiffSummary::from_results(&results);
        assert!(summary.mismatches.contains(&"first".to_string()));
        assert!(summary.mismatches.contains(&"second".to_string()));
    }
}
