//! Stable JSON contract consumed by `divergence.core.sandbox`.

use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

use crate::capability::Capability;

const MAX_OBSERVATIONS: usize = 10_000;

#[derive(Debug, Serialize)]
pub struct Observation {
    pub capability: &'static str,
    pub syscall: String,
    pub target: String,
    pub decoy: bool,
    /// Whether the kernel actually completed the operation. Attempts blocked by the
    /// sandbox remain useful evidence, but are never presented as successful access.
    pub succeeded: bool,
    pub result: i64,
}

#[derive(Debug, Serialize)]
pub struct Coverage {
    pub syscalls_observed: u64,
    pub observations_dropped: u64,
    pub entrypoints_invoked: usize,
    pub entrypoints_completed: usize,
    pub entrypoints_failed: usize,
    pub confinement_enforced: bool,
    pub exited_cleanly: bool,
    pub exit_code: i32,
    pub timed_out: bool,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema: &'static str,
    pub runner_version: &'static str,
    pub capabilities: BTreeSet<&'static str>,
    pub observations: Vec<Observation>,
    pub coverage: Coverage,
    pub evidence: BTreeMap<&'static str, String>,
    pub limitations: Vec<String>,
}

impl Report {
    pub fn new() -> Self {
        Self {
            schema: "divergence.sandbox/1",
            runner_version: env!("CARGO_PKG_VERSION"),
            capabilities: BTreeSet::new(),
            observations: Vec::new(),
            coverage: Coverage {
                syscalls_observed: 0,
                observations_dropped: 0,
                entrypoints_invoked: 0,
                entrypoints_completed: 0,
                entrypoints_failed: 0,
                confinement_enforced: false,
                exited_cleanly: false,
                exit_code: -1,
                timed_out: false,
            },
            evidence: BTreeMap::new(),
            limitations: Vec::new(),
        }
    }

    pub fn observe(
        &mut self,
        cap: Capability,
        syscall: &str,
        target: &str,
        decoy: bool,
        succeeded: bool,
        result: i64,
    ) {
        self.capabilities.insert(cap.as_str());
        self.evidence.entry(cap.as_str()).or_insert_with(|| {
            format!(
                "{}({}) -> {}{}",
                syscall,
                target,
                result,
                if succeeded { "" } else { " (blocked/failed)" }
            )
        });
        if self.observations.len() >= MAX_OBSERVATIONS {
            self.coverage.observations_dropped += 1;
            return;
        }
        self.observations.push(Observation {
            capability: cap.as_str(),
            syscall: syscall.to_string(),
            target: target.to_string(),
            decoy,
            succeeded,
            result,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_is_part_of_observation_and_evidence() {
        let mut report = Report::new();
        report.observe(
            Capability::NetOutbound,
            "connect",
            "203.0.113.1:443",
            false,
            false,
            -1,
        );
        assert!(!report.observations[0].succeeded);
        assert!(report.evidence["net_outbound"].contains("blocked/failed"));
    }
}
