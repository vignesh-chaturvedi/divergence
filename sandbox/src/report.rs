//! The JSON contract with the Python core.
//!
//! Stable and small on purpose: the crate is consumed over this interface, so the Python
//! side never links against Rust and an absent sandbox is a missing file rather than a
//! build failure.

use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

use crate::capability::Capability;

#[derive(Debug, Serialize)]
pub struct Observation {
    pub capability: &'static str,
    pub syscall: String,
    /// The path or address the syscall touched, when there is one.
    pub target: String,
    /// True when this touched a decoy credential planted by the overlay.
    pub decoy: bool,
}

#[derive(Debug, Serialize)]
pub struct Coverage {
    /// Syscalls actually observed. Dynamic analysis only sees paths that execute, so this
    /// number travels with every finding rather than sitting in a footnote.
    pub syscalls_observed: u64,
    pub entrypoints_invoked: usize,
    pub exited_cleanly: bool,
    pub exit_code: i32,
    pub timed_out: bool,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema: &'static str,
    pub capabilities: BTreeSet<&'static str>,
    pub observations: Vec<Observation>,
    pub coverage: Coverage,
    pub evidence: BTreeMap<&'static str, String>,
    /// Anything the runner could not do — a missing kernel feature, a dropped privilege.
    /// Reported rather than silently degrading the result.
    pub limitations: Vec<String>,
}

impl Report {
    pub fn new() -> Self {
        Report {
            schema: "divergence.sandbox/1",
            capabilities: BTreeSet::new(),
            observations: Vec::new(),
            coverage: Coverage {
                syscalls_observed: 0,
                entrypoints_invoked: 0,
                exited_cleanly: false,
                exit_code: -1,
                timed_out: false,
            },
            evidence: BTreeMap::new(),
            limitations: Vec::new(),
        }
    }

    pub fn observe(&mut self, cap: Capability, syscall: &str, target: &str, decoy: bool) {
        self.capabilities.insert(cap.as_str());
        self.evidence
            .entry(cap.as_str())
            .or_insert_with(|| format!("{}({})", syscall, target));
        self.observations.push(Observation {
            capability: cap.as_str(),
            syscall: syscall.to_string(),
            target: target.to_string(),
            decoy,
        });
    }
}
