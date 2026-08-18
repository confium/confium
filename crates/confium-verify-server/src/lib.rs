//! Library surface for the HTTP verification service: exposes the
//! handlers and the canonical router so integrators (and tests) can
//! mount the same routes as the binary.

pub mod handlers;

pub use handlers::{AppState, VerifySignatifRequest};

/// The canonical router, shared by the binary and tests.
pub fn router() -> axum::Router {
    axum::Router::new()
        .route(
            "/verify/composite",
            axum::routing::post(handlers::verify_composite),
        )
        .route(
            "/verify/signatif",
            axum::routing::post(handlers::verify_signatif),
        )
        .route(
            "/verify/inclusion",
            axum::routing::post(handlers::verify_inclusion),
        )
        .route("/healthz", axum::routing::get(handlers::healthz))
        .with_state(AppState)
}
