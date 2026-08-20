//! Confinement: Landlock filesystem restriction and the decoy overlay.
//!
//! Landlock is applied in the child *after* fork and before exec, because a Landlock
//! ruleset is inherited across exec and cannot be relaxed — which is exactly the property
//! that makes it trustworthy here.

use landlock::{
    Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus, ABI,
};
use std::fs;
use std::io;
use std::path::Path;

use crate::capability::DECOY_PATHS;

/// Plant decoy credentials the artifact has no legitimate reason to touch.
///
/// §05: "Anything that reads them is caught red-handed with no ambiguity to adjudicate."
/// That is the point — a real credential read is arguable ("it is a credential manager"),
/// but a read of a fake key that exists only inside this overlay is not.
pub fn plant_decoys(root: &Path) -> io::Result<Vec<String>> {
    let mut planted = Vec::new();
    for path in DECOY_PATHS {
        let full = root.join(path.trim_start_matches('/'));
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(
            &full,
            "-----BEGIN OPENSSH PRIVATE KEY-----\nDIVERGENCE-DECOY-DO-NOT-USE\n-----END OPENSSH PRIVATE KEY-----\n",
        )?;
        planted.push(full.to_string_lossy().into_owned());
    }
    Ok(planted)
}

/// Restrict the calling process to `allowed`, read-only, plus write access to `writable`.
///
/// Returns a limitation string when the kernel cannot fully enforce the request, rather
/// than pretending it did. A sandbox that silently degrades is worse than no sandbox: the
/// results look identical and mean something different.
pub fn restrict_filesystem(allowed: &[&Path], writable: &[&Path]) -> Result<Option<String>, String> {
    let abi = ABI::V1;
    let read_only = AccessFs::from_read(abi);
    let read_write = AccessFs::from_all(abi);

    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| format!("landlock handle_access: {e}"))?
        .create()
        .map_err(|e| format!("landlock create: {e}"))?;

    for path in allowed {
        if path.exists() {
            ruleset = ruleset
                .add_rules(landlock::path_beneath_rules(&[path], read_only))
                .map_err(|e| format!("landlock rule {}: {e}", path.display()))?;
        }
    }
    for path in writable {
        if path.exists() {
            ruleset = ruleset
                .add_rules(landlock::path_beneath_rules(&[path], read_write))
                .map_err(|e| format!("landlock rule {}: {e}", path.display()))?;
        }
    }

    let status = ruleset
        .restrict_self()
        .map_err(|e| format!("landlock restrict_self: {e}"))?;

    Ok(match status.ruleset {
        RulesetStatus::FullyEnforced => None,
        RulesetStatus::PartiallyEnforced => {
            Some("landlock only partially enforced — kernel ABI older than requested".into())
        }
        RulesetStatus::NotEnforced => {
            Some("landlock NOT enforced — filesystem confinement unavailable on this kernel".into())
        }
    })
}

/// Landlock ABI the running kernel supports. 0 means unavailable.
pub fn landlock_abi() -> i32 {
    // The version query is the documented way to probe support and needs no privileges.
    unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, std::ptr::null::<u8>(), 0usize, 1u32) as i32 }
}
