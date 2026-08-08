//! CRD definitions for Confium Kubernetes resources.

use serde::{Deserialize, Serialize};

/// `ConfiumSigningCeremony` custom resource spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningCeremonySpec {
    /// Threshold scheme: `cmp20` or `gg18`.
    pub scheme: String,
    /// Threshold T.
    pub threshold: u32,
    /// Total party count N.
    #[serde(rename = "partyCount")]
    pub party_count: u32,
    /// Reference to the message to sign.
    #[serde(rename = "messageRef")]
    pub message_ref: ConfigMapRef,
    /// Reference to where the output signature should be stored.
    #[serde(rename = "outputRef")]
    pub output_ref: SecretRef,
}

/// Reference to a ConfigMap containing the message to sign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigMapRef {
    pub config_map: String,
    pub key: String,
}

/// Reference to a Secret where the signature will be stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRef {
    pub secret: String,
}

/// Status of a signing ceremony.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningCeremonyStatus {
    pub phase: CeremonyPhase,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub signature_secret: Option<String>,
    pub error: Option<String>,
}

/// Phases of a signing ceremony lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CeremonyPhase {
    /// Ceremony has been created but not started.
    Pending,
    /// DKG is in progress.
    KeygenRunning,
    /// DKG complete; signing in progress.
    Signing,
    /// Ceremony completed; signature stored.
    Completed,
    /// Ceremony failed.
    Failed,
}

/// The full CRD object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningCeremony {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub metadata: ObjectMeta,
    pub spec: SigningCeremonySpec,
    pub status: Option<SigningCeremonyStatus>,
}

/// Kubernetes object metadata (simplified).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectMeta {
    pub name: String,
    pub namespace: Option<String>,
    #[serde(default)]
    pub labels: std::collections::BTreeMap<String, String>,
}

/// Generate the CRD YAML for `kubectl apply`.
pub fn crd_yaml() -> String {
    r#"apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: confiumsigningceremonies.confium.org
spec:
  group: confium.org
  names:
    kind: ConfiumSigningCeremony
    listKind: ConfiumSigningCeremonyList
    plural: confiumsigningceremonies
    singular: confiumsigningceremony
  scope: Namespaced
  versions:
    - name: v1alpha1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          properties:
            spec:
              type: object
              required: [scheme, threshold, partyCount]
              properties:
                scheme:
                  type: string
                  enum: [cmp20, gg18]
                threshold:
                  type: integer
                  minimum: 1
                partyCount:
                  type: integer
                  minimum: 1
                messageRef:
                  type: object
                  properties:
                    configMap: { type: string }
                    key: { type: string }
                outputRef:
                  type: object
                  properties:
                    secret: { type: string }
            status:
              type: object
              properties:
                phase:
                  type: string
                  enum: [pending, keygenrunning, signing, completed, failed]
                startedAt: { type: string }
                completedAt: { type: string }
                signatureSecret: { type: string }
                error: { type: string }
"#
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crd_yaml_is_valid_yaml() {
        let yaml = crd_yaml();
        let parsed: serde_yaml::Value = serde_yaml::from_str(&yaml).expect("CRD YAML must parse");
        assert_eq!(parsed["kind"], "CustomResourceDefinition");
    }

    #[test]
    fn ceremony_spec_round_trips() {
        let spec = SigningCeremonySpec {
            scheme: "cmp20".to_string(),
            threshold: 3,
            party_count: 5,
            message_ref: ConfigMapRef {
                config_map: "release-artifact".to_string(),
                key: "release.tar.gz".to_string(),
            },
            output_ref: SecretRef {
                secret: "release-signature".to_string(),
            },
        };
        let json = serde_json::to_string(&spec).unwrap();
        let parsed: SigningCeremonySpec = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.scheme, "cmp20");
        assert_eq!(parsed.threshold, 3);
    }
}
