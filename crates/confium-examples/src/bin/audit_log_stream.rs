//! Audit log stream demonstration.

fn main() {
    println!("=== Confium Audit Log Demo ===");
    println!();
    let _cfm = confium_core::Confium::new();
    println!("Confium initialized. Audit logger configured.");
    println!();
    println!("Default sink: ~/.local/share/confium/log/audit.jsonl");
    println!("Override:     CONFIUM_AUDIT_LOG=/path/to/file");
    println!("Disable:      Confium::new_with_audit(AuditLogger::disabled())");
    println!();
    println!("Example JSONL events:");
    println!("  ts=2026-07-25T13:05:22Z event=plugin_load plugin=botan");
    println!("  ts=2026-07-25T13:05:23Z event=tc_session_start scheme=FROST-ed25519");
    println!();
    println!("No secret bytes ever appear in the audit log.");
}
