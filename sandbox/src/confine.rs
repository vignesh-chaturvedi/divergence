//! Fail-closed confinement and the private per-run filesystem.

use landlock::{
    Access, AccessFs, AccessNet, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus, ABI,
};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::capability::DECOY_HOME_PATHS;

pub struct PrivateOverlay {
    pub root: PathBuf,
    pub home: PathBuf,
    pub scratch: PathBuf,
    pub driver: PathBuf,
    pub decoys: Vec<String>,
}

impl PrivateOverlay {
    /// Create a fresh directory with mode 0700. `parent` is a directory in which a unique
    /// run directory is created; it is never reused as the run directory itself.
    pub fn create(parent: Option<&Path>, driver_source: &str) -> io::Result<Self> {
        let base = parent
            .map(Path::to_path_buf)
            .unwrap_or_else(std::env::temp_dir);
        let metadata = fs::symlink_metadata(&base)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "overlay parent must be a real directory, not a symlink",
            ));
        }

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let mut root = None;
        for attempt in 0..32_u32 {
            let candidate = base.join(format!(
                "divergence-overlay-{}-{nonce}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&candidate) {
                Ok(()) => {
                    fs::set_permissions(&candidate, fs::Permissions::from_mode(0o700))?;
                    root = Some(candidate);
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        let root = root.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "could not allocate a unique overlay",
            )
        })?;
        let home = root.join("home");
        let scratch = root.join("scratch");
        fs::create_dir(&home)?;
        fs::create_dir(&scratch)?;
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(&scratch, fs::Permissions::from_mode(0o700))?;

        let mut decoys = Vec::new();
        for relative in DECOY_HOME_PATHS {
            let full = home.join(relative);
            if let Some(parent) = full.parent() {
                fs::create_dir_all(parent)?;
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
            }
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&full)?;
            file.write_all(
                b"-----BEGIN OPENSSH PRIVATE KEY-----\nDIVERGENCE-DECOY-DO-NOT-USE\n-----END OPENSSH PRIVATE KEY-----\n",
            )?;
            file.sync_all()?;
            fs::set_permissions(&full, fs::Permissions::from_mode(0o400))?;
            decoys.push(full.to_string_lossy().into_owned());
        }

        let driver = root.join("drive.py");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&driver)?;
        file.write_all(driver_source.as_bytes())?;
        file.sync_all()?;
        fs::set_permissions(&driver, fs::Permissions::from_mode(0o400))?;

        Ok(Self {
            root,
            home,
            scratch,
            driver,
            decoys,
        })
    }
}

impl Drop for PrivateOverlay {
    fn drop(&mut self) {
        // This directory was uniquely created by this process and never supplied directly by
        // the caller, so cleanup cannot recursively target user data.
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// Apply Landlock v4 filesystem and TCP restrictions. No TCP port rules are added, so
/// bind and connect are denied. Partial enforcement is an error: the artifact is not run.
pub fn restrict(artifact: &Path, overlay: &PrivateOverlay) -> Result<(), String> {
    let abi = ABI::V4;
    let read_only = AccessFs::from_read(abi);
    let read_write = AccessFs::from_all(abi);

    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .map_err(|error| format!("landlock filesystem rights: {error}"))?
        .handle_access(AccessNet::from_all(abi))
        .map_err(|error| format!("landlock network rights: {error}"))?
        .create()
        .map_err(|error| format!("landlock create: {error}"))?;

    let mut readable = vec![artifact, overlay.root.as_path()];
    for system in ["/usr", "/usr/local", "/bin", "/lib", "/lib64"] {
        let path = Path::new(system);
        if path.exists() {
            readable.push(path);
        }
    }
    // Avoid granting the whole of /etc or /dev: a system may keep service credentials or
    // privileged devices there. These are the small set ordinary dynamic linking, name
    // resolution, time handling, and Python startup may legitimately need.
    for system_file in [
        "/etc/ld.so.cache",
        "/etc/localtime",
        "/etc/nsswitch.conf",
        "/etc/hosts",
        "/etc/resolv.conf",
        "/etc/passwd",
        "/etc/group",
        "/etc/ssl/certs",
        "/dev/null",
        "/dev/urandom",
        "/dev/random",
    ] {
        let path = Path::new(system_file);
        if path.exists() {
            readable.push(path);
        }
    }
    for path in readable {
        ruleset = ruleset
            .add_rules(landlock::path_beneath_rules(&[path], read_only))
            .map_err(|error| format!("landlock read rule {}: {error}", path.display()))?;
    }
    ruleset = ruleset
        .add_rules(landlock::path_beneath_rules(
            &[overlay.scratch.as_path()],
            read_write,
        ))
        .map_err(|error| format!("landlock scratch rule: {error}"))?;

    let status = ruleset
        .restrict_self()
        .map_err(|error| format!("landlock restrict_self: {error}"))?;
    if status.ruleset != RulesetStatus::FullyEnforced || !status.no_new_privs {
        return Err(format!(
            "landlock v4 not fully enforced (ruleset={:?}, no_new_privs={})",
            status.ruleset, status.no_new_privs
        ));
    }
    Ok(())
}

/// Landlock ABI the running kernel supports. Zero means unavailable.
pub fn landlock_abi() -> i32 {
    let result = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<u8>(),
            0usize,
            1u32,
        ) as i32
    };
    result.max(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlay_is_private_unique_and_maps_home_decoys() {
        let first = PrivateOverlay::create(None, "# driver").unwrap();
        let second = PrivateOverlay::create(None, "# driver").unwrap();
        assert_ne!(first.root, second.root);
        assert!(first
            .decoys
            .iter()
            .all(|path| path.starts_with(first.home.to_string_lossy().as_ref())));
        assert_eq!(
            fs::metadata(&first.root).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
}
