//! Middleware pipeline — unified request processing chain.

use std::sync::Arc;

/// A request context passed through the pipeline.
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub request_type: String,
    pub signer_id: Option<String>,
    pub quorum_id: Option<String>,
    pub session_id: Option<String>,
    pub payload_size: usize,
}

/// Middleware result: continue or reject.
#[derive(Debug, Clone)]
pub enum MiddlewareResult {
    Continue,
    Reject(String),
}

/// Middleware trait — each stage processes the request.
pub trait Middleware: Send + Sync {
    fn name(&self) -> &str;
    fn process(&self, ctx: &RequestContext) -> MiddlewareResult;
}

/// The pipeline: runs middlewares in order, stops on first rejection.
pub struct Pipeline {
    middlewares: Vec<Box<dyn Middleware>>,
}

impl Pipeline {
    pub fn new() -> Self {
        Self { middlewares: Vec::new() }
    }

    pub fn add(&mut self, mw: Box<dyn Middleware>) -> &mut Self {
        self.middlewares.push(mw);
        self
    }

    pub fn execute(&self, ctx: &RequestContext) -> Result<(), String> {
        for mw in &self.middlewares {
            match mw.process(ctx) {
                MiddlewareResult::Continue => {}
                MiddlewareResult::Reject(reason) => {
                    return Err(format!("{} rejected: {}", mw.name(), reason));
                }
            }
        }
        Ok(())
    }

    pub fn middleware_count(&self) -> usize {
        self.middlewares.len()
    }
}

impl Default for Pipeline {
    fn default() -> Self { Self::new() }
}

// Built-in middlewares

/// Rate limiting middleware (uses the rate limiter).
pub struct RateLimitMiddleware {
    pub max_per_second: u32,
}

impl Middleware for RateLimitMiddleware {
    fn name(&self) -> &str { "rate-limiter" }
    fn process(&self, ctx: &RequestContext) -> MiddlewareResult {
        // Simplified: check payload size as a proxy for load
        if ctx.payload_size > 1_000_000 {
            MiddlewareResult::Reject("payload too large".into())
        } else {
            MiddlewareResult::Continue
        }
    }
}

/// Authentication middleware.
pub struct AuthMiddleware {
    pub required: bool,
}

impl Middleware for AuthMiddleware {
    fn name(&self) -> &str { "auth" }
    fn process(&self, ctx: &RequestContext) -> MiddlewareResult {
        if self.required && ctx.signer_id.is_none() {
            MiddlewareResult::Reject("authentication required".into())
        } else {
            MiddlewareResult::Continue
        }
    }
}

/// Policy enforcement middleware.
pub struct PolicyMiddleware;

impl Middleware for PolicyMiddleware {
    fn name(&self) -> &str { "policy" }
    fn process(&self, ctx: &RequestContext) -> MiddlewareResult {
        if ctx.quorum_id.is_none() && ctx.request_type != "health_check" {
            MiddlewareResult::Reject("quorum_id required".into())
        } else {
            MiddlewareResult::Continue
        }
    }
}

/// Backpressure middleware.
pub struct BackpressureMiddleware {
    pub max_payload: usize,
}

impl Middleware for BackpressureMiddleware {
    fn name(&self) -> &str { "backpressure" }
    fn process(&self, ctx: &RequestContext) -> MiddlewareResult {
        if ctx.payload_size > self.max_payload {
            MiddlewareResult::Reject(format!("payload {} exceeds max {}", ctx.payload_size, self.max_payload))
        } else {
            MiddlewareResult::Continue
        }
    }
}

/// Logging middleware (always continues).
pub struct LoggingMiddleware;

impl Middleware for LoggingMiddleware {
    fn name(&self) -> &str { "logging" }
    fn process(&self, _ctx: &RequestContext) -> MiddlewareResult {
        MiddlewareResult::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx(req_type: &str) -> RequestContext {
        RequestContext {
            request_type: req_type.into(),
            signer_id: Some("alice".into()),
            quorum_id: Some("q1".into()),
            session_id: None,
            payload_size: 100,
        }
    }

    #[test]
    fn empty_pipeline_always_passes() {
        let pipeline = Pipeline::new();
        assert!(pipeline.execute(&make_ctx("test")).is_ok());
    }

    #[test]
    fn auth_rejects_unauthenticated() {
        let mut pipeline = Pipeline::new();
        pipeline.add(Box::new(AuthMiddleware { required: true }));
        let mut ctx = make_ctx("test");
        ctx.signer_id = None;
        assert!(pipeline.execute(&ctx).is_err());
    }

    #[test]
    fn auth_allows_authenticated() {
        let mut pipeline = Pipeline::new();
        pipeline.add(Box::new(AuthMiddleware { required: true }));
        assert!(pipeline.execute(&make_ctx("test")).is_ok());
    }

    #[test]
    fn full_pipeline_passes_valid_request() {
        let mut pipeline = Pipeline::new();
        pipeline
            .add(Box::new(RateLimitMiddleware { max_per_second: 100 }))
            .add(Box::new(AuthMiddleware { required: true }))
            .add(Box::new(PolicyMiddleware))
            .add(Box::new(BackpressureMiddleware { max_payload: 10_000 }))
            .add(Box::new(LoggingMiddleware));
        assert!(pipeline.execute(&make_ctx("sign")).is_ok());
        assert_eq!(pipeline.middleware_count(), 5);
    }

    #[test]
    fn backpressure_rejects_large_payload() {
        let mut pipeline = Pipeline::new();
        pipeline.add(Box::new(BackpressureMiddleware { max_payload: 100 }));
        let mut ctx = make_ctx("test");
        ctx.payload_size = 200;
        assert!(pipeline.execute(&ctx).is_err());
    }

    #[test]
    fn policy_allows_health_check_without_quorum() {
        let mut pipeline = Pipeline::new();
        pipeline.add(Box::new(PolicyMiddleware));
        let mut ctx = make_ctx("health_check");
        ctx.quorum_id = None;
        assert!(pipeline.execute(&ctx).is_ok());
    }

    #[test]
    fn policy_rejects_sign_without_quorum() {
        let mut pipeline = Pipeline::new();
        pipeline.add(Box::new(PolicyMiddleware));
        let mut ctx = make_ctx("sign");
        ctx.quorum_id = None;
        assert!(pipeline.execute(&ctx).is_err());
    }

    #[test]
    fn first_rejection_stops_pipeline() {
        let mut pipeline = Pipeline::new();
        pipeline.add(Box::new(AuthMiddleware { required: true }));
        pipeline.add(Box::new(LoggingMiddleware));
        let mut ctx = make_ctx("test");
        ctx.signer_id = None;
        let result = pipeline.execute(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("auth"));
    }

    #[test]
    fn rate_limit_rejects_large_payload() {
        let mut pipeline = Pipeline::new();
        pipeline.add(Box::new(RateLimitMiddleware { max_per_second: 10 }));
        let mut ctx = make_ctx("test");
        ctx.payload_size = 2_000_000;
        assert!(pipeline.execute(&ctx).is_err());
    }
}
