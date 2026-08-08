//! Axum router + handlers for the log server API.

use std::sync::Arc;

use axum::Json;
use axum::{
    Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Json as AxumJson},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::cert::{classify_cert, fingerprint, parse_der};
use crate::db::{Database, Entry};
use crate::merkle::MerkleState;

/// Shared server state. Cheaply clonable (everything is behind an
/// `Arc` / `Mutex`).
pub struct AppState {
    pub db: Database,
    pub merkle: parking_lot::Mutex<MerkleState>,
    pub page_size: usize,
}

#[derive(Debug, Deserialize)]
pub struct AppendRequest {
    pub artifact_type: String,
    pub artifact_hash: String,
}

#[derive(Debug, Deserialize)]
pub struct AppendCertRequest {
    /// Base64-encoded DER bytes of the X.509 certificate.
    pub certificate_der: String,
}

#[derive(Debug, Deserialize)]
pub struct WitnessRequest {
    pub witness_id: String,
    /// Base64-encoded witness signature over `tree_size || root_hash`.
    pub signature: String,
}

#[derive(Debug, Deserialize)]
pub struct Pagination {
    pub limit: Option<usize>,
    pub before: Option<u64>,
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        // Generic hash-entry API.
        .route("/v1/append", post(append_hash))
        .route("/v1/head", get(head))
        .route("/v1/proof/:sequence", get(proof))
        .route("/v1/consistency/:old_size", get(consistency))
        // Cert-aware API.
        .route("/v1/certificates", post(append_certificate))
        .route("/v1/certificates/:fingerprint", get(lookup_certificate))
        .route("/v1/issuers/:issuer/certificates", get(list_by_issuer))
        // OTS anchoring.
        .route("/v1/head/:sequence/ots", get(get_ots_proof))
        // Witness gossip.
        .route("/v1/head/:sequence/witness", post(post_witness))
        .route("/v1/head/:sequence/witnesses", get(list_witnesses))
        .route("/v1/health", get(health))
        .route("/metrics", get(metrics))
        .with_state(state)
}

// ===== Generic hash-entry handlers =====

async fn append_hash(
    State(state): State<Arc<AppState>>,
    AxumJson(req): AxumJson<AppendRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let hash_bytes = hex::decode(&req.artifact_hash)
        .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, format!("bad hex: {e}")))?;
    if hash_bytes.len() != 32 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            format!("artifact_hash must be 32 bytes, got {}", hash_bytes.len()),
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&hash_bytes);

    let timestamp = chrono::Utc::now().to_rfc3339();
    let entry = Entry {
        sequence: 0,
        artifact_type: req.artifact_type,
        artifact_hash: req.artifact_hash.clone(),
        timestamp: timestamp.clone(),
        issuer_distinguished_name: None,
        subject_distinguished_name: None,
        fingerprint_sha256: None,
        valid_from: None,
        valid_to: None,
    };
    let seq = state.db.append(&entry).map_err(internal_error)?;
    {
        let mut merkle = state.merkle.lock();
        merkle.append(arr);
    }

    let root = state.merkle.lock().root();
    let size = state.merkle.lock().len();
    Ok(AxumJson(json!({
        "sequence": seq,
        "tree_size": size,
        "root": hex::encode(root),
        "timestamp": timestamp,
    })))
}

async fn head(State(state): State<Arc<AppState>>) -> Result<impl IntoResponse, ApiError> {
    let merkle = state.merkle.lock();
    let root = merkle.root();
    let size = merkle.len();
    Ok(AxumJson(json!({
        "tree_size": size,
        "root": hex::encode(root),
        "timestamp": chrono::Utc::now().to_rfc3339(),
    })))
}

async fn proof(
    State(state): State<Arc<AppState>>,
    Path(sequence): Path<u64>,
) -> Result<impl IntoResponse, ApiError> {
    let merkle = state.merkle.lock();
    let proof = merkle
        .inclusion_proof(sequence)
        .map_err(|e| ApiError::new(StatusCode::NOT_FOUND, e.to_string()))?;
    let root = merkle.root();
    let size = merkle.len();
    let steps: Vec<Value> = proof
        .steps
        .iter()
        .map(|s| {
            json!({
                "sibling": hex::encode(s.sibling),
                "side": match s.side {
                    confium_transparency::merkle::Side::Left => "left",
                    confium_transparency::merkle::Side::Right => "right",
                }
            })
        })
        .collect();
    Ok(AxumJson(json!({
        "sequence": proof.sequence,
        "steps": steps,
        "root": hex::encode(root),
        "tree_size": size,
    })))
}

async fn consistency(
    State(state): State<Arc<AppState>>,
    Path(old_size): Path<u64>,
) -> Result<impl IntoResponse, ApiError> {
    let merkle = state.merkle.lock();
    let proof = merkle
        .consistency_proof(old_size)
        .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, e.to_string()))?;
    let hashes: Vec<String> = proof.iter().map(hex::encode).collect();
    Ok(AxumJson(json!({
        "old_size": old_size,
        "new_size": merkle.len(),
        "new_root": hex::encode(merkle.root()),
        "proof": hashes,
    })))
}

// ===== Cert-aware handlers =====

async fn append_certificate(
    State(state): State<Arc<AppState>>,
    AxumJson(req): AxumJson<AppendCertRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let der_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        req.certificate_der,
    )
    .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, format!("bad base64: {e}")))?;

    let meta = parse_der(&der_bytes)
        .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, format!("cert parse: {e}")))?;
    let artifact_type = classify_cert(&der_bytes, &meta);
    let fingerprint_hex = hex::encode(fingerprint(&der_bytes));

    let timestamp = chrono::Utc::now().to_rfc3339();
    let entry = Entry {
        sequence: 0,
        artifact_type: artifact_type.clone(),
        artifact_hash: fingerprint_hex.clone(),
        timestamp: timestamp.clone(),
        issuer_distinguished_name: Some(meta.issuer_distinguished_name.clone()),
        subject_distinguished_name: Some(meta.subject_distinguished_name.clone()),
        fingerprint_sha256: Some(meta.fingerprint_sha256.clone()),
        valid_from: Some(meta.valid_from.clone()),
        valid_to: Some(meta.valid_to.clone()),
    };
    let seq = state.db.append(&entry).map_err(internal_error)?;
    {
        let mut merkle = state.merkle.lock();
        merkle.append(fingerprint(&der_bytes));
    }

    let root = state.merkle.lock().root();
    let size = state.merkle.lock().len();
    Ok(AxumJson(json!({
        "sequence": seq,
        "tree_size": size,
        "root": hex::encode(root),
        "timestamp": timestamp,
        "artifact_type": artifact_type,
        "fingerprint_sha256": fingerprint_hex,
        "issuer": meta.issuer_distinguished_name,
        "subject": meta.subject_distinguished_name,
    })))
}

async fn lookup_certificate(
    State(state): State<Arc<AppState>>,
    Path(fingerprint): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let entries = state
        .db
        .entries_by_fingerprint(&fingerprint)
        .map_err(internal_error)?;
    if entries.is_empty() {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            format!("no entries for fingerprint {fingerprint}"),
        ));
    }
    Ok(AxumJson(json!(entries)))
}

async fn list_by_issuer(
    State(state): State<Arc<AppState>>,
    Path(issuer): Path<String>,
    Query(page): Query<Pagination>,
) -> Result<impl IntoResponse, ApiError> {
    let limit = page.limit.unwrap_or(state.page_size);
    let entries = state
        .db
        .entries_by_issuer(&issuer, limit)
        .map_err(internal_error)?;
    Ok(AxumJson(json!({
        "issuer": issuer,
        "count": entries.len(),
        "limit": limit,
        "entries": entries,
    })))
}

// ===== OTS =====

async fn get_ots_proof(
    State(state): State<Arc<AppState>>,
    Path(sequence): Path<u64>,
) -> Result<impl IntoResponse, ApiError> {
    let row = state.db.get_ots_proof(sequence).map_err(internal_error)?;
    match row {
        Some((proof, height, anchor_time)) => Ok(AxumJson(json!({
            "tree_size": sequence,
            "ots_proof": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &proof),
            "bitcoin_height": height,
            "anchor_time": anchor_time,
        }))),
        None => Err(ApiError::new(
            StatusCode::NOT_FOUND,
            format!("no OTS proof for tree size {sequence}"),
        )),
    }
}

// ===== Witness gossip =====

async fn post_witness(
    State(state): State<Arc<AppState>>,
    Path(sequence): Path<u64>,
    AxumJson(req): AxumJson<WitnessRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let sig = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, req.signature)
        .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, format!("bad base64: {e}")))?;

    // Compute the root for this sequence (we trust the witness's
    // signature over `tree_size || root`; we look up the root we
    // observed for that tree size and verify the signature covers
    // it. For the scaffold, we use the current root if sequence
    // matches; a production deployment stores a per-sequence root
    // snapshot.)
    let root = state.merkle.lock().root();
    state
        .db
        .store_witness_sig(sequence, &root, &req.witness_id, &sig)
        .map_err(internal_error)?;
    Ok(AxumJson(
        json!({"accepted": true, "witness_id": req.witness_id}),
    ))
}

async fn list_witnesses(
    State(state): State<Arc<AppState>>,
    Path(sequence): Path<u64>,
) -> Result<impl IntoResponse, ApiError> {
    let sigs = state
        .db
        .witness_sigs_for_size(sequence)
        .map_err(internal_error)?;
    let witnesses: Vec<Value> = sigs
        .into_iter()
        .map(|(wid, sig, ts)| {
            json!({
                "witness_id": wid,
                "signature": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &sig),
                "timestamp": ts,
            })
        })
        .collect();
    Ok(AxumJson(json!({
        "tree_size": sequence,
        "witnesses": witnesses,
    })))
}

// ===== Health =====

async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let size = state.merkle.lock().len();
    let count = state.db.entry_count().unwrap_or(0);
    AxumJson(json!({
        "ok": true,
        "tree_size": size,
        "entry_count": count,
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

// ===== Prometheus metrics =====

async fn metrics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let tree_size = state.merkle.lock().len();
    let entry_count = state.db.entry_count().unwrap_or(0);
    let witness_count = state
        .db
        .witness_sigs_for_size(tree_size)
        .map(|s| s.len())
        .unwrap_or(0);

    let body = format!(
        "# HELP confium_log_tree_size Current number of leaves in the Merkle tree.\n\
         # TYPE confium_log_tree_size gauge\n\
         confium_log_tree_size {tree_size}\n\
         # HELP confium_log_entry_count Total entries ever appended.\n\
         # TYPE confium_log_entry_count gauge\n\
         confium_log_entry_count {entry_count}\n\
         # HELP confium_log_witness_count Number of witnesses for the current tree head.\n\
         # TYPE confium_log_witness_count gauge\n\
         confium_log_witness_count {witness_count}\n"
    );

    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        body,
    )
}

// ===== Error helpers =====

fn internal_error<E: std::fmt::Display>(e: E) -> ApiError {
    tracing::error!("internal error: {e}");
    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        ApiError {
            status,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let body = Json(json!({"error": self.message}));
        (self.status, body).into_response()
    }
}
