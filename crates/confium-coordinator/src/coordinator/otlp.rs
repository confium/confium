//! OTLP (OpenTelemetry Protocol) span exporter.
//!
//! Converts tracing spans to OTLP-compatible JSON for export to
//! Jaeger, Zipkin, or any OTLP-compatible backend.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// An OTLP span — OpenTelemetry-compatible trace span.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtlpSpan {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub name: String,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub attributes: Vec<OtlpAttribute>,
    pub status: OtlpStatus,
}

/// A key-value attribute on a span.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtlpAttribute {
    pub key: String,
    pub value: String,
}

/// Span status.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct OtlpStatus {
    pub code: String,
    pub message: Option<String>,
}

impl OtlpStatus {
    pub fn ok() -> Self {
        Self {
            code: "ok".into(),
            message: None,
        }
    }
    pub fn error(msg: &str) -> Self {
        Self {
            code: "error".into(),
            message: Some(msg.into()),
        }
    }
}

/// Batch of spans for export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanBatch {
    pub resource_spans: Vec<ResourceSpans>,
}

/// Resource-level spans (one per service).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceSpans {
    pub resource: ResourceAttributes,
    pub scope_spans: Vec<ScopeSpans>,
}

/// Resource attributes (service name, version, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceAttributes {
    pub attributes: Vec<OtlpAttribute>,
}

/// Scope-level spans.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeSpans {
    pub scope: ScopeInfo,
    pub spans: Vec<OtlpSpan>,
}

/// Scope metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeInfo {
    pub name: String,
    pub version: String,
}

/// Build an OTLP span from a tracing event.
pub fn build_span(
    trace_id: &str,
    span_id: &str,
    name: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    attributes: Vec<(&str, &str)>,
) -> OtlpSpan {
    OtlpSpan {
        trace_id: trace_id.into(),
        span_id: span_id.into(),
        parent_span_id: None,
        name: name.into(),
        start_time: start,
        end_time: end,
        attributes: attributes
            .into_iter()
            .map(|(k, v)| OtlpAttribute {
                key: k.into(),
                value: v.into(),
            })
            .collect(),
        status: OtlpStatus::ok(),
    }
}

/// Build a complete OTLP export batch.
pub fn build_export_batch(
    service_name: &str,
    service_version: &str,
    spans: Vec<OtlpSpan>,
) -> SpanBatch {
    SpanBatch {
        resource_spans: vec![ResourceSpans {
            resource: ResourceAttributes {
                attributes: vec![
                    OtlpAttribute {
                        key: "service.name".into(),
                        value: service_name.into(),
                    },
                    OtlpAttribute {
                        key: "service.version".into(),
                        value: service_version.into(),
                    },
                ],
            },
            scope_spans: vec![ScopeSpans {
                scope: ScopeInfo {
                    name: "confium-tc".into(),
                    version: service_version.into(),
                },
                spans,
            }],
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn span_has_trace_id() {
        let span = build_span("trace-1", "span-1", "test", Utc::now(), Utc::now(), vec![]);
        assert_eq!(span.trace_id, "trace-1");
        assert_eq!(span.span_id, "span-1");
    }

    #[test]
    fn span_attributes_preserved() {
        let span = build_span(
            "t",
            "s",
            "n",
            Utc::now(),
            Utc::now(),
            vec![("key1", "val1"), ("key2", "val2")],
        );
        assert_eq!(span.attributes.len(), 2);
        assert_eq!(span.attributes[0].key, "key1");
    }

    #[test]
    fn status_ok_has_no_message() {
        let status = OtlpStatus::ok();
        assert_eq!(status.code, "ok");
        assert!(status.message.is_none());
    }

    #[test]
    fn status_error_has_message() {
        let status = OtlpStatus::error("failed");
        assert_eq!(status.code, "error");
        assert_eq!(status.message.as_deref(), Some("failed"));
    }

    #[test]
    fn export_batch_serializes() {
        let span = build_span("t", "s", "n", Utc::now(), Utc::now(), vec![]);
        let batch = build_export_batch("confium-coord", "0.3.0", vec![span]);
        let json = serde_json::to_string(&batch).unwrap();
        assert!(json.contains("confium-coord"));
        assert!(json.contains("resource_spans"));
    }

    #[test]
    fn export_batch_has_resource_attributes() {
        let batch = build_export_batch("svc", "1.0", vec![]);
        assert_eq!(batch.resource_spans.len(), 1);
        let attrs = &batch.resource_spans[0].resource.attributes;
        assert!(
            attrs
                .iter()
                .any(|a| a.key == "service.name" && a.value == "svc")
        );
    }

    #[test]
    fn span_round_trips_json() {
        let span = build_span(
            "t1",
            "s1",
            "operation",
            Utc::now(),
            Utc::now(),
            vec![("a", "b")],
        );
        let json = serde_json::to_string(&span).unwrap();
        let recovered: OtlpSpan = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.trace_id, "t1");
        assert_eq!(recovered.attributes.len(), 1);
    }
}
