//! Coordinator factory — builder pattern with dependency injection.

use crate::coordinator::coordinator::Coordinator;
use crate::coordinator::session::SessionRequest;
use crate::di_container::Container;

/// Builder for assembling a fully configured coordinator.
pub struct CoordinatorBuilder {
    container: Container,
    default_threshold: u32,
    default_party_count: u32,
    default_unlock_minutes: u32,
}

impl CoordinatorBuilder {
    pub fn new() -> Self {
        Self {
            container: Container::new(),
            default_threshold: 2,
            default_party_count: 3,
            default_unlock_minutes: 60,
        }
    }

    /// Set default threshold for new sessions.
    pub fn with_threshold(mut self, t: u32) -> Self {
        self.default_threshold = t;
        self
    }

    /// Set default party count.
    pub fn with_party_count(mut self, n: u32) -> Self {
        self.default_party_count = n;
        self
    }

    /// Set default unlock window.
    pub fn with_unlock_minutes(mut self, m: u32) -> Self {
        self.default_unlock_minutes = m;
        self
    }

    /// Register a custom dependency.
    pub fn with_dependency<T, F>(mut self, factory: F) -> Self
    where
        T: Send + Sync + 'static,
        F: Fn() -> T + Send + Sync + 'static,
    {
        self.container.register(factory);
        self
    }

    /// Build the coordinator.
    pub fn build(&mut self) -> Coordinator {
        Coordinator::new()
    }

    /// Create a session with default parameters.
    pub fn create_default_session(
        &mut self,
        coordinator: &mut Coordinator,
        quorum_id: &str,
        message: Vec<u8>,
    ) -> Result<String, String> {
        let request = SessionRequest {
            quorum_id: quorum_id.into(),
            scheme: "CMP20".into(),
            message,
            threshold: self.default_threshold,
            num_parties: self.default_party_count,
            unlock_window_minutes: self.default_unlock_minutes,
            requested_by: "factory".into(),
        };
        coordinator.create_session(request).map_err(|e| format!("{e:?}"))
    }

    /// Access the DI container.
    pub fn container(&mut self) -> &mut Container {
        &mut self.container
    }
}

impl Default for CoordinatorBuilder {
    fn default() -> Self { Self::new() }
}

/// Simple test helper: create a coordinator with preset config.
pub fn test_coordinator(threshold: u32, party_count: u32) -> Coordinator {
    let mut builder = CoordinatorBuilder::new()
        .with_threshold(threshold)
        .with_party_count(party_count);
    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_default() {
        let mut builder = CoordinatorBuilder::new();
        let coord = builder.build();
        assert_eq!(coord.session_count(), 0);
    }

    #[test]
    fn builder_custom_threshold() {
        let mut builder = CoordinatorBuilder::new().with_threshold(3);
        let mut coord = builder.build();
        let result = builder.create_default_session(&mut coord, "q1", vec![0; 32]);
        assert!(result.is_ok());
    }

    #[test]
    fn builder_custom_party_count() {
        let mut builder = CoordinatorBuilder::new()
            .with_threshold(2)
            .with_party_count(5);
        let mut coord = builder.build();
        let result = builder.create_default_session(&mut coord, "q1", vec![0; 32]);
        assert!(result.is_ok());
    }

    #[test]
    fn builder_custom_unlock() {
        let mut builder = CoordinatorBuilder::new()
            .with_threshold(2)
            .with_unlock_minutes(120);
        let mut coord = builder.build();
        let result = builder.create_default_session(&mut coord, "q1", vec![0; 32]);
        assert!(result.is_ok());
    }

    #[test]
    fn builder_dependency_injection() {
        let mut builder = CoordinatorBuilder::new()
            .with_dependency(|| 42i32);
        let container = builder.container();
        let result: Option<i32> = container.resolve();
        assert_eq!(result, Some(42));
    }

    #[test]
    fn test_coordinator_helper() {
        let coord = test_coordinator(2, 3);
        assert_eq!(coord.session_count(), 0);
    }

    #[test]
    fn multiple_sessions_via_builder() {
        let mut builder = CoordinatorBuilder::new().with_threshold(2);
        let mut coord = builder.build();
        let s1 = builder.create_default_session(&mut coord, "q1", vec![0; 32]).unwrap();
        let s2 = builder.create_default_session(&mut coord, "q2", vec![1; 32]).unwrap();
        assert_ne!(s1, s2);
        assert_eq!(coord.session_count(), 2);
    }
}
