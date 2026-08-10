//! Protocol version negotiation.

use serde::{Deserialize, Serialize};

/// Current protocol version.
pub const PROTOCOL_VERSION: u32 = 1;

/// Version negotiation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionHandshake {
    pub client_version: u32,
    pub min_supported: u32,
}

/// Version negotiation response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionResponse {
    pub server_version: u32,
    pub accepted: bool,
    pub negotiated_version: u32,
    pub reason: Option<String>,
}

/// Check if a client version is compatible with this server.
pub fn negotiate(client_handshake: &VersionHandshake) -> VersionResponse {
    if client_handshake.client_version > PROTOCOL_VERSION {
        if client_handshake.min_supported <= PROTOCOL_VERSION {
            return VersionResponse {
                server_version: PROTOCOL_VERSION,
                accepted: true,
                negotiated_version: PROTOCOL_VERSION,
                reason: Some(format!(
                    "downgraded from {} to {}",
                    client_handshake.client_version, PROTOCOL_VERSION
                )),
            };
        }
        return VersionResponse {
            server_version: PROTOCOL_VERSION,
            accepted: false,
            negotiated_version: 0,
            reason: Some("client requires newer protocol".into()),
        };
    }
    if client_handshake.client_version < 1 {
        return VersionResponse {
            server_version: PROTOCOL_VERSION,
            accepted: false,
            negotiated_version: 0,
            reason: Some("invalid client version".into()),
        };
    }
    VersionResponse {
        server_version: PROTOCOL_VERSION,
        accepted: true,
        negotiated_version: client_handshake.client_version.min(PROTOCOL_VERSION),
        reason: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_version_accepted() {
        let hs = VersionHandshake { client_version: 1, min_supported: 1 };
        let resp = negotiate(&hs);
        assert!(resp.accepted);
        assert_eq!(resp.negotiated_version, 1);
    }

    #[test]
    fn newer_client_downgrades() {
        let hs = VersionHandshake { client_version: 5, min_supported: 1 };
        let resp = negotiate(&hs);
        assert!(resp.accepted);
        assert_eq!(resp.negotiated_version, PROTOCOL_VERSION);
    }

    #[test]
    fn client_requires_newer_rejected() {
        let hs = VersionHandshake { client_version: 5, min_supported: 5 };
        let resp = negotiate(&hs);
        assert!(!resp.accepted);
    }

    #[test]
    fn invalid_version_rejected() {
        let hs = VersionHandshake { client_version: 0, min_supported: 0 };
        let resp = negotiate(&hs);
        assert!(!resp.accepted);
    }

    #[test]
    fn handshake_serializes() {
        let hs = VersionHandshake { client_version: 1, min_supported: 1 };
        let json = serde_json::to_string(&hs).unwrap();
        assert!(json.contains("client_version"));
    }
}
