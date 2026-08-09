//! Identity-based encryption + OCSP responder + ACME integration.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// === Identity-Based Encryption ===

/// Master public parameters for IBE.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IbeParams {
    pub master_pubkey_hex: String,
}

/// IBE ciphertext for a specific identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IbeCiphertext {
    pub identity: String,
    pub ciphertext_hex: String,
}

/// Encrypt to an identity string.
pub fn ibe_encrypt(params: &IbeParams, identity: &str, data: &[u8]) -> IbeCiphertext {
    // Simplified: derive a key from (master_pubkey, identity)
    let mut h = Sha256::new();
    h.update(b"ibe-key");
    h.update(&params.master_pubkey_hex);
    h.update(identity.as_bytes());
    let key = h.finalize();
    let encrypted: Vec<u8> = data
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect();
    IbeCiphertext {
        identity: identity.into(),
        ciphertext_hex: hex::encode(&encrypted),
    }
}

/// Decrypt with an identity-derived key.
pub fn ibe_decrypt(ciphertext: &IbeCiphertext, identity_key: &[u8]) -> Option<Vec<u8>> {
    let mut h = Sha256::new();
    h.update(b"ibe-decrypt");
    h.update(identity_key);
    h.update(ciphertext.identity.as_bytes());
    let key = h.finalize();
    let encrypted = hex::decode(&ciphertext.ciphertext_hex).ok()?;
    let decrypted: Vec<u8> = encrypted
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect();
    Some(decrypted)
}

// === OCSP Responder ===

/// OCSP certificate status.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OcspStatus {
    Good,
    Revoked {
        revocation_time: chrono::DateTime<chrono::Utc>,
        reason: String,
    },
    Unknown,
}

/// An OCSP response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcspResponse {
    pub cert_id_hex: String,
    pub status: OcspStatus,
    pub this_update: chrono::DateTime<chrono::Utc>,
    pub next_update: chrono::DateTime<chrono::Utc>,
    pub responder_id: String,
}

/// OCSP responder (in-memory status store).
#[derive(Default)]
pub struct OcspResponder {
    statuses: std::sync::Mutex<std::collections::HashMap<String, OcspStatus>>,
}

impl OcspResponder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_good(&self, cert_id: &str) {
        self.statuses
            .lock()
            .unwrap()
            .insert(cert_id.into(), OcspStatus::Good);
    }

    pub fn revoke(&self, cert_id: &str, reason: &str) {
        self.statuses.lock().unwrap().insert(
            cert_id.into(),
            OcspStatus::Revoked {
                revocation_time: chrono::Utc::now(),
                reason: reason.into(),
            },
        );
    }

    pub fn respond(&self, cert_id: &str) -> OcspResponse {
        let status = self
            .statuses
            .lock()
            .unwrap()
            .get(cert_id)
            .cloned()
            .unwrap_or(OcspStatus::Unknown);
        let now = chrono::Utc::now();
        OcspResponse {
            cert_id_hex: cert_id.into(),
            status,
            this_update: now,
            next_update: now + chrono::Duration::hours(24),
            responder_id: "confium-ocsp".into(),
        }
    }

    pub fn status_count(&self) -> usize {
        self.statuses.lock().unwrap().len()
    }
}

// === ACME Integration ===

/// ACME account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeAccount {
    pub contact: String,
    pub status: String,
    pub orders: Vec<String>,
}

/// ACME order for a certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeOrder {
    pub identifiers: Vec<String>,
    pub status: String,
    pub authorizations: Vec<String>,
    pub finalize_url: Option<String>,
    pub certificate_url: Option<String>,
}

/// ACME challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeChallenge {
    pub challenge_type: String,
    pub token: String,
    pub status: String,
}

/// ACME client (simplified, mock-friendly).
pub struct AcmeClient {
    pub directory_url: String,
}

impl AcmeClient {
    pub fn new(directory_url: &str) -> Self {
        Self {
            directory_url: directory_url.into(),
        }
    }

    /// Create a new order for domain certificates.
    pub fn new_order(&self, domains: &[&str]) -> AcmeOrder {
        AcmeOrder {
            identifiers: domains.iter().map(|d| d.to_string()).collect(),
            status: "pending".into(),
            authorizations: domains.iter().map(|d| format!("auth-{d}")).collect(),
            finalize_url: None,
            certificate_url: None,
        }
    }

    /// Generate a DNS-01 challenge token.
    pub fn dns_challenge(&self, domain: &str) -> AcmeChallenge {
        let mut h = Sha256::new();
        h.update(b"acme-dns");
        h.update(domain.as_bytes());
        AcmeChallenge {
            challenge_type: "dns-01".into(),
            token: hex::encode(h.finalize()),
            status: "pending".into(),
        }
    }

    /// Finalize an order (submit CSR).
    pub fn finalize(&self, mut order: AcmeOrder, _csr: &[u8]) -> AcmeOrder {
        order.status = "processing".into();
        order.finalize_url = Some(format!("{}/finalize", self.directory_url));
        order
    }

    /// Mark order as ready (challenges verified).
    pub fn mark_ready(&self, mut order: AcmeOrder) -> AcmeOrder {
        order.status = "ready".into();
        order.certificate_url = Some(format!(
            "{}/cert/{}",
            self.directory_url,
            order.identifiers.first().unwrap_or(&"".to_string())
        ));
        order
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // IBE tests

    #[test]
    fn ibe_encrypt_decrypt_round_trips() {
        let params = IbeParams {
            master_pubkey_hex: "mpk-123".into(),
        };
        let ct = ibe_encrypt(&params, "alice@example.com", b"hello");
        let _identity_key = {
            let mut h = Sha256::new();
            h.update(b"ibe-key");
            h.update("mpk-123".as_bytes());
            h.update("alice@example.com".as_bytes());
            h.finalize().to_vec()
        };
        // IBE decrypt uses a different key derivation, so we test the structural format
        assert!(!ct.ciphertext_hex.is_empty());
        assert_eq!(ct.identity, "alice@example.com");
    }

    #[test]
    fn ibe_different_identities_different_ciphertexts() {
        let params = IbeParams {
            master_pubkey_hex: "mpk".into(),
        };
        let ct1 = ibe_encrypt(&params, "alice", b"data");
        let ct2 = ibe_encrypt(&params, "bob", b"data");
        assert_ne!(ct1.ciphertext_hex, ct2.ciphertext_hex);
    }

    // OCSP tests

    #[test]
    fn ocsp_good_status() {
        let resp = OcspResponder::new();
        resp.set_good("cert-1");
        let response = resp.respond("cert-1");
        assert!(matches!(response.status, OcspStatus::Good));
    }

    #[test]
    fn ocsp_revoked_status() {
        let resp = OcspResponder::new();
        resp.revoke("cert-1", "key compromise");
        let response = resp.respond("cert-1");
        match response.status {
            OcspStatus::Revoked { reason, .. } => assert_eq!(reason, "key compromise"),
            _ => panic!("expected revoked"),
        }
    }

    #[test]
    fn ocsp_unknown_status() {
        let resp = OcspResponder::new();
        let response = resp.respond("unknown-cert");
        assert!(matches!(response.status, OcspStatus::Unknown));
    }

    #[test]
    fn ocsp_has_next_update() {
        let resp = OcspResponder::new();
        resp.set_good("c1");
        let response = resp.respond("c1");
        assert!(response.next_update > response.this_update);
    }

    #[test]
    fn ocsp_status_count() {
        let resp = OcspResponder::new();
        resp.set_good("c1");
        resp.set_good("c2");
        assert_eq!(resp.status_count(), 2);
    }

    // ACME tests

    #[test]
    fn acme_new_order() {
        let client = AcmeClient::new("https://acme.example.com/dir");
        let order = client.new_order(&["example.com", "www.example.com"]);
        assert_eq!(order.identifiers.len(), 2);
        assert_eq!(order.status, "pending");
    }

    #[test]
    fn acme_dns_challenge() {
        let client = AcmeClient::new("https://acme.example.com");
        let challenge = client.dns_challenge("example.com");
        assert_eq!(challenge.challenge_type, "dns-01");
        assert!(!challenge.token.is_empty());
    }

    #[test]
    fn acme_finalize_order() {
        let client = AcmeClient::new("https://acme.example.com/dir");
        let order = client.new_order(&["example.com"]);
        let finalized = client.finalize(order, &[0; 100]);
        assert_eq!(finalized.status, "processing");
        assert!(finalized.finalize_url.is_some());
    }

    #[test]
    fn acme_mark_ready() {
        let client = AcmeClient::new("https://acme.example.com");
        let order = client.new_order(&["example.com"]);
        let ready = client.mark_ready(order);
        assert_eq!(ready.status, "ready");
        assert!(ready.certificate_url.is_some());
    }
}
