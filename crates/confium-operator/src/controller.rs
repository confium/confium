//! Controller loop — watches for ConfiumSigningCeremony CRs and
//! reconciles them.
//!
//! The controller is a simplified reconciliation loop. In production
//! this would use `kube-rs` to watch the Kubernetes API; the scaffold
//! demonstrates the logic without the Kubernetes client dependency.

use std::time::Duration;

pub struct CeremonyController {
    namespace: Option<String>,
}

impl CeremonyController {
    pub fn new(namespace: Option<String>) -> Self {
        Self { namespace }
    }

    /// Run the reconciliation loop indefinitely.
    pub async fn run(&self) -> anyhow::Result<()> {
        loop {
            self.reconcile_once().await?;
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    }

    /// One reconciliation pass. In production: list all
    /// ConfiumSigningCeremony CRs in the namespace, find those in
    /// Pending phase, and drive them through the lifecycle.
    pub async fn reconcile_once(&self) -> anyhow::Result<()> {
        tracing::info!(namespace = ?self.namespace, "reconciliation pass");
        // Scaffold: no actual Kubernetes client. The real loop would:
        // 1. List ConfiumSigningCeremony CRs via kube-rs.
        // 2. Filter for phase == Pending.
        // 3. For each: read messageRef ConfigMap, run DKG + sign,
        //    write signature to outputRef Secret, update status.
        Ok(())
    }

    /// Execute a threshold signing ceremony (the core logic, separate
    /// from Kubernetes plumbing so it's testable in isolation).
    pub fn execute_ceremony(
        scheme: &str,
        threshold: u32,
        party_count: u32,
        message: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        tracing::info!(
            scheme,
            threshold,
            party_count,
            msg_len = message.len(),
            "executing ceremony"
        );

        let (public_key, shares) = match scheme {
            "cmp20" => {
                let kg = confium_tc_cmp20::inprocess::keygen(threshold, party_count as usize)?;
                (kg.public_key, kg.shares)
            }
            "gg18" => {
                let kg = confium_tc_gg18::inprocess::keygen(threshold, party_count as usize)?;
                (kg.public_key, kg.shares)
            }
            other => anyhow::bail!("unknown scheme: {other}"),
        };

        let sig = match scheme {
            "cmp20" => confium_tc_cmp20::inprocess::sign(&shares, threshold, message)?,
            "gg18" => confium_tc_gg18::inprocess::sign(&shares, threshold, message)?,
            _ => unreachable!(),
        };

        tracing::info!(
            pk_len = public_key.len(),
            sig_len = sig.len(),
            "ceremony completed"
        );

        Ok(sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execute_ceremony_cmp20() {
        let sig = CeremonyController::execute_ceremony("cmp20", 2, 3, b"release artifact").unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn execute_ceremony_gg18() {
        let sig = CeremonyController::execute_ceremony("gg18", 2, 3, b"release artifact").unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn execute_ceremony_rejects_unknown_scheme() {
        assert!(CeremonyController::execute_ceremony("bogus", 2, 3, b"msg").is_err());
    }
}
