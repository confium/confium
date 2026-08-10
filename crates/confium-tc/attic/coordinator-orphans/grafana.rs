//! Grafana dashboard JSON generation for coordinator metrics.
//!
//! Produces a Grafana dashboard JSON that visualizes the Prometheus
//! metrics exported by the coordinator. Import directly via the
//! Grafana UI (Dashboards → Import → paste JSON).

use serde::{Deserialize, Serialize};

/// A Grafana dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dashboard {
    pub title: String,
    pub uid: String,
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub version: u32,
    pub refresh: String,
    pub time: TimeRange,
    pub templating: Templating,
    pub panels: Vec<Panel>,
}

/// Time range for the dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRange {
    pub from: String,
    pub to: String,
}

/// Templating variables.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Templating {
    pub list: Vec<TemplateVar>,
}

/// A template variable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateVar {
    pub name: String,
    #[serde(rename = "type")]
    pub var_type: String,
    pub query: String,
    pub current: TemplateCurrent,
}

/// Current value for a template variable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateCurrent {
    pub text: String,
    pub value: String,
}

/// A dashboard panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Panel {
    pub id: u32,
    pub title: String,
    #[serde(rename = "type")]
    pub panel_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub datasource: Option<String>,
    pub grid_pos: GridPos,
    pub targets: Vec<Target>,
}

/// Grid position.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GridPos {
    pub h: u32,
    pub w: u32,
    pub x: u32,
    pub y: u32,
}

/// A Prometheus query target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub expr: String,
    pub legend_format: String,
    pub ref_id: String,
}

/// Generate the default Confium coordinator dashboard JSON.
pub fn generate_dashboard() -> String {
    let dashboard = Dashboard {
        title: "Confium Coordinator".into(),
        uid: "confium-coordinator".into(),
        schema_version: 39,
        version: 1,
        refresh: "10s".into(),
        time: TimeRange {
            from: "now-1h".into(),
            to: "now".into(),
        },
        templating: Templating {
            list: vec![TemplateVar {
                name: "datasource".into(),
                var_type: "datasource".into(),
                query: "Prometheus".into(),
                current: TemplateCurrent {
                    text: "Prometheus".into(),
                    value: "Prometheus".into(),
                },
            }],
        },
        panels: vec![
            Panel {
                id: 1,
                title: "Sessions Created (rate)".into(),
                panel_type: "stat".into(),
                datasource: Some("$datasource".into()),
                grid_pos: GridPos { h: 4, w: 6, x: 0, y: 0 },
                targets: vec![Target {
                    expr: "rate(confium_sessions_created_total[5m])".into(),
                    legend_format: "created/s".into(),
                    ref_id: "A".into(),
                }],
            },
            Panel {
                id: 2,
                title: "Active Sessions".into(),
                panel_type: "gauge".into(),
                datasource: Some("$datasource".into()),
                grid_pos: GridPos { h: 4, w: 6, x: 6, y: 0 },
                targets: vec![Target {
                    expr: "confium_active_sessions".into(),
                    legend_format: "active".into(),
                    ref_id: "A".into(),
                }],
            },
            Panel {
                id: 3,
                title: "Registered Signers".into(),
                panel_type: "stat".into(),
                datasource: Some("$datasource".into()),
                grid_pos: GridPos { h: 4, w: 6, x: 12, y: 0 },
                targets: vec![Target {
                    expr: "confium_registered_signers".into(),
                    legend_format: "signers".into(),
                    ref_id: "A".into(),
                }],
            },
            Panel {
                id: 4,
                title: "Session Lifecycle".into(),
                panel_type: "timeseries".into(),
                datasource: Some("$datasource".into()),
                grid_pos: GridPos { h: 8, w: 24, x: 0, y: 4 },
                targets: vec![
                    Target {
                        expr: "rate(confium_sessions_created_total[5m])".into(),
                        legend_format: "Created".into(),
                        ref_id: "A".into(),
                    },
                    Target {
                        expr: "rate(confium_sessions_completed_total[5m])".into(),
                        legend_format: "Completed".into(),
                        ref_id: "B".into(),
                    },
                    Target {
                        expr: "rate(confium_sessions_expired_total[5m])".into(),
                        legend_format: "Expired".into(),
                        ref_id: "C".into(),
                    },
                    Target {
                        expr: "rate(confium_sessions_aborted_total[5m])".into(),
                        legend_format: "Aborted".into(),
                        ref_id: "D".into(),
                    },
                ],
            },
            Panel {
                id: 5,
                title: "Aggregation Success Rate".into(),
                panel_type: "stat".into(),
                datasource: Some("$datasource".into()),
                grid_pos: GridPos { h: 4, w: 8, x: 0, y: 12 },
                targets: vec![Target {
                    expr: "1 - (rate(confium_aggregations_failed_total[5m]) / clamp_min(rate(confium_aggregations_attempted_total[5m]), 0.001))".into(),
                    legend_format: "success %".into(),
                    ref_id: "A".into(),
                }],
            },
            Panel {
                id: 6,
                title: "Bytes Processed (rate)".into(),
                panel_type: "timeseries".into(),
                datasource: Some("$datasource".into()),
                grid_pos: GridPos { h: 8, w: 12, x: 8, y: 12 },
                targets: vec![Target {
                    expr: "rate(confium_bytes_processed_total[5m])".into(),
                    legend_format: "bytes/s".into(),
                    ref_id: "A".into(),
                }],
            },
        ],
    };
    serde_json::to_string_pretty(&dashboard).expect("dashboard serialization")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_valid_json() {
        let json = generate_dashboard();
        assert!(!json.is_empty());
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_object());
    }

    #[test]
    fn dashboard_has_title() {
        let json = generate_dashboard();
        let parsed: Dashboard = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.title, "Confium Coordinator");
    }

    #[test]
    fn dashboard_has_uid() {
        let json = generate_dashboard();
        let parsed: Dashboard = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.uid, "confium-coordinator");
    }

    #[test]
    fn dashboard_has_6_panels() {
        let json = generate_dashboard();
        let parsed: Dashboard = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.panels.len(), 6);
    }

    #[test]
    fn panels_have_prometheus_targets() {
        let json = generate_dashboard();
        let parsed: Dashboard = serde_json::from_str(&json).unwrap();
        for panel in &parsed.panels {
            assert!(!panel.targets.is_empty());
            for target in &panel.targets {
                assert!(!target.expr.is_empty());
                assert!(target.expr.contains("confium_"));
            }
        }
    }

    #[test]
    fn has_datasource_templating() {
        let json = generate_dashboard();
        let parsed: Dashboard = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.templating.list.len(), 1);
        assert_eq!(parsed.templating.list[0].name, "datasource");
    }

    #[test]
    fn session_lifecycle_panel_has_4_targets() {
        let json = generate_dashboard();
        let parsed: Dashboard = serde_json::from_str(&json).unwrap();
        let lifecycle = parsed.panels.iter().find(|p| p.id == 4).unwrap();
        assert_eq!(lifecycle.targets.len(), 4);
    }

    #[test]
    fn json_is_importable_to_grafana() {
        let json = generate_dashboard();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.get("title").is_some());
        assert!(parsed.get("panels").is_some());
        assert!(parsed.get("schemaVersion").is_some());
        assert!(parsed.get("refresh").is_some());
    }
}
