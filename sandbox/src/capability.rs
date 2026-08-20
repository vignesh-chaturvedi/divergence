//! The shared capability vocabulary.
//!
//! Deliberately identical to the Python side's `core/vocabulary.py`. The whole point of
//! normalising here is that the divergence engine consumes B_dynamic without special-casing
//! it — if these two lists drift, the set algebra in A6 starts comparing incomparable things.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    FsRead,
    FsWrite,
    FsDelete,
    NetOutbound,
    ProcSpawn,
    EnvRead,
    SecretsRead,
    DynamicEval,
}

impl Capability {
    /// The exact string A4 emits. Serialised into the JSON the Python side parses.
    pub fn as_str(&self) -> &'static str {
        match self {
            Capability::FsRead => "fs_read",
            Capability::FsWrite => "fs_write",
            Capability::FsDelete => "fs_delete",
            Capability::NetOutbound => "net_outbound",
            Capability::ProcSpawn => "proc_spawn",
            Capability::EnvRead => "env_read",
            Capability::SecretsRead => "secrets_read",
            Capability::DynamicEval => "dynamic_eval",
        }
    }
}

/// Paths seeded with decoy credentials. A read of any of these is unambiguous: there is no
/// legitimate reason to open a fake SSH key that exists only inside the sandbox overlay.
pub const DECOY_PATHS: &[&str] = &[
    "/root/.ssh/id_rsa",
    "/root/.ssh/id_ed25519",
    "/root/.aws/credentials",
    "/root/.netrc",
    "/root/.config/divergence-token",
];

pub fn is_decoy(path: &str) -> bool {
    DECOY_PATHS.iter().any(|d| path == *d)
        || path.contains("/.ssh/")
        || path.contains("/.aws/")
        || path.ends_with("/.netrc")
}
