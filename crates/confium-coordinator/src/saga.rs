//! Saga pattern for multi-step ceremony management.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A saga step with forward action and compensation.
#[derive(Debug, Clone)]
pub struct SagaStep {
    pub name: String,
    pub completed: bool,
    pub failed: bool,
}

/// Saga execution state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SagaState {
    Running,
    Completed,
    Compensating,
    Compensated,
    Failed,
}

/// A saga orchestrating multi-step ceremonies.
pub struct Saga {
    pub saga_id: String,
    pub steps: Vec<SagaStep>,
    pub state: SagaState,
    pub current_step: usize,
    pub results: HashMap<String, String>,
}

impl Saga {
    pub fn new(saga_id: &str, step_names: &[&str]) -> Self {
        let steps = step_names
            .iter()
            .map(|name| SagaStep {
                name: name.to_string(),
                completed: false,
                failed: false,
            })
            .collect();
        Self {
            saga_id: saga_id.into(),
            steps,
            state: SagaState::Running,
            current_step: 0,
            results: HashMap::new(),
        }
    }

    /// Execute the saga forward. Returns Ok when all steps complete,
    /// Err when a step fails (triggers compensation).
    pub fn execute<F>(&mut self, mut step_fn: F) -> Result<(), String>
    where
        F: FnMut(&str) -> Result<String, String>,
    {
        while self.current_step < self.steps.len() {
            let step = &mut self.steps[self.current_step];
            match step_fn(&step.name) {
                Ok(result) => {
                    self.results.insert(step.name.clone(), result);
                    self.steps[self.current_step].completed = true;
                    self.current_step += 1;
                }
                Err(e) => {
                    self.steps[self.current_step].failed = true;
                    self.state = SagaState::Compensating;
                    return Err(e);
                }
            }
        }
        self.state = SagaState::Completed;
        Ok(())
    }

    /// Compensate (roll back) completed steps in reverse order.
    pub fn compensate<F>(&mut self, mut compensate_fn: F) -> Result<(), String>
    where
        F: FnMut(&str) -> Result<(), String>,
    {
        self.state = SagaState::Compensating;
        let mut completed_indices: Vec<usize> = self
            .steps
            .iter()
            .enumerate()
            .filter(|(_, s)| s.completed)
            .map(|(i, _)| i)
            .collect();
        completed_indices.reverse();

        for idx in completed_indices {
            let step_name = self.steps[idx].name.clone();
            if let Err(e) = compensate_fn(&step_name) {
                self.state = SagaState::Failed;
                return Err(e);
            }
            self.steps[idx].completed = false;
        }

        self.state = SagaState::Compensated;
        Ok(())
    }

    pub fn progress(&self) -> f64 {
        let completed = self.steps.iter().filter(|s| s.completed).count();
        completed as f64 / self.steps.len().max(1) as f64
    }

    pub fn completed_steps(&self) -> Vec<&str> {
        self.steps
            .iter()
            .filter(|s| s.completed)
            .map(|s| s.name.as_str())
            .collect()
    }

    pub fn step_count(&self) -> usize {
        self.steps.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_steps_succeed() {
        let mut saga = Saga::new("s1", &["step1", "step2", "step3"]);
        saga.execute(|name| Ok(format!("done-{name}"))).unwrap();
        assert_eq!(saga.state, SagaState::Completed);
        assert_eq!(saga.progress(), 1.0);
    }

    #[test]
    fn step_failure_triggers_compensation() {
        let mut saga = Saga::new("s1", &["step1", "step2", "step3"]);
        let result = saga.execute(|name| {
            if name == "step2" {
                Err("step2 failed".into())
            } else {
                Ok("ok".into())
            }
        });
        assert!(result.is_err());
        assert_eq!(saga.state, SagaState::Compensating);
        // step1 completed, step2 failed, step3 not reached
        assert!(saga.steps[0].completed);
        assert!(saga.steps[1].failed);
        assert!(!saga.steps[2].completed);
    }

    #[test]
    fn compensation_rolls_back() {
        let mut saga = Saga::new("s1", &["step1", "step2", "step3"]);
        saga.execute(|name| {
            if name == "step3" {
                Err("fail".into())
            } else {
                Ok("ok".into())
            }
        })
        .unwrap_err();
        saga.compensate(|_| Ok(())).unwrap();
        assert_eq!(saga.state, SagaState::Compensated);
        assert_eq!(saga.completed_steps().len(), 0);
    }

    #[test]
    fn first_step_failure_no_compensation_needed() {
        let mut saga = Saga::new("s1", &["step1", "step2"]);
        saga.execute(|_| Err("immediate fail".into())).unwrap_err();
        saga.compensate(|_| Ok(())).unwrap();
        assert_eq!(saga.state, SagaState::Compensated);
    }

    #[test]
    fn progress_tracking() {
        let mut saga = Saga::new("s1", &["a", "b", "c", "d"]);
        saga.execute(|name| {
            if name == "c" {
                Err("stop".into())
            } else {
                Ok("ok".into())
            }
        })
        .unwrap_err();
        assert!((saga.progress() - 0.5).abs() < 0.01);
    }

    #[test]
    fn empty_saga_completes() {
        let mut saga = Saga::new("empty", &[]);
        saga.execute(|_| Ok("ok".into())).unwrap();
        assert_eq!(saga.state, SagaState::Completed);
    }

    #[test]
    fn results_recorded() {
        let mut saga = Saga::new("s1", &["step1", "step2"]);
        saga.execute(|name| Ok(format!("result-{name}"))).unwrap();
        assert_eq!(saga.results.get("step1").unwrap(), "result-step1");
        assert_eq!(saga.results.get("step2").unwrap(), "result-step2");
    }

    #[test]
    fn compensation_failure_marks_failed() {
        let mut saga = Saga::new("s1", &["step1", "step2"]);
        saga.execute(|name| {
            if name == "step2" {
                Err("fail".into())
            } else {
                Ok("ok".into())
            }
        })
        .unwrap_err();
        saga.compensate(|name| {
            if name == "step1" {
                Err("compensation failed".into())
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert_eq!(saga.state, SagaState::Failed);
    }

    #[test]
    fn step_count() {
        let saga = Saga::new("s1", &["a", "b", "c"]);
        assert_eq!(saga.step_count(), 3);
    }
}
