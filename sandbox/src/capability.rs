//! The capability vocabulary shared with the Python core.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    FsRead,
    FsWrite,
    FsDelete,
    NetOutbound,
    NetListen,
    ProcSpawn,
    SecretsRead,
}

impl Capability {
    pub fn as_str(&self) -> &'static str {
        match self {
            Capability::FsRead => "fs_read",
            Capability::FsWrite => "fs_write",
            Capability::FsDelete => "fs_delete",
            Capability::NetOutbound => "net_outbound",
            Capability::NetListen => "net_listen",
            Capability::ProcSpawn => "proc_spawn",
            Capability::SecretsRead => "secrets_read",
        }
    }
}

/// Decoys are relative to the private HOME created for each run. Keeping this list
/// relative is important: `$HOME/.ssh/id_rsa` must resolve to the file that was planted,
/// not to an unrelated `overlay/root/.ssh/id_rsa` path.
pub const DECOY_HOME_PATHS: &[&str] = &[
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
    ".aws/credentials",
    ".netrc",
    ".config/divergence-token",
];

pub fn is_decoy(path: &str, planted: &[String]) -> bool {
    planted.iter().any(|candidate| candidate == path)
}

pub fn is_secret_path(path: &str) -> bool {
    path.contains("/.ssh/")
        || path.contains("/.aws/")
        || path.ends_with("/.netrc")
        || path.contains("/credentials")
        || path.contains("/secrets/")
        || path.contains("/keychain")
        || path.ends_with("/etc/shadow")
        || path.ends_with("/etc/gshadow")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoys_require_an_exact_planted_path() {
        let planted = vec!["/tmp/run/home/.ssh/id_rsa".to_string()];
        assert!(is_decoy("/tmp/run/home/.ssh/id_rsa", &planted));
        assert!(!is_decoy("/root/.ssh/id_rsa", &planted));
        assert!(!is_decoy("/tmp/run/home/.ssh/other", &planted));
    }

    #[test]
    fn credential_paths_are_high_signal_without_being_decoys() {
        assert!(is_secret_path("/root/.ssh/id_ed25519"));
        assert!(is_secret_path("/etc/shadow"));
        assert!(!is_secret_path("/project/notes.txt"));
    }
}
