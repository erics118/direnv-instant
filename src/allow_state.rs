use sha2::{Digest, Sha256};
use std::env;
use std::path::{Path, PathBuf};

// direnv's approval state for envrc_dir/.envrc, read from direnv's own store:
// allow = sha256(abs "\n" contents), deny = sha256(abs "\n"), mutually exclusive.
// 0 allowed, 2 denied, 1 not-allowed. Ignores direnv's whitelist config (unused here).
pub fn allow_state(envrc_dir: &Path) -> u8 {
    let envrc = envrc_dir.join(".envrc");
    let Ok(contents) = std::fs::read(&envrc) else {
        return 1;
    };
    let path = envrc.to_string_lossy();
    let data = direnv_data_dir();

    let mut h = Sha256::new();
    h.update(path.as_bytes());
    h.update(b"\n");
    h.update(&contents);
    if data.join("allow").join(hex(&h.finalize())).exists() {
        return 0;
    }

    let mut h = Sha256::new();
    h.update(path.as_bytes());
    h.update(b"\n");
    if data.join("deny").join(hex(&h.finalize())).exists() {
        return 2;
    }

    1
}

fn direnv_data_dir() -> PathBuf {
    match env::var("XDG_DATA_HOME") {
        Ok(x) if !x.is_empty() => PathBuf::from(x).join("direnv"),
        _ => PathBuf::from(env::var("HOME").unwrap_or_default()).join(".local/share/direnv"),
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// guards the hard-coded scheme above: if a future direnv changes how it keys
// allow/deny, native read and `direnv status` disagree and this fails.
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::Command;
    use tinyjson::JsonValue;

    fn direnv(dir: &Path, sub: &str) {
        Command::new("direnv")
            .arg(sub)
            .arg(".")
            .current_dir(dir)
            .output()
            .expect("run direnv");
    }

    fn status_found_allowed(dir: &Path) -> u8 {
        let out = Command::new("direnv")
            .args(["status", "--json"])
            .current_dir(dir)
            .output()
            .expect("run direnv status");
        let v: JsonValue = String::from_utf8_lossy(&out.stdout)
            .parse()
            .expect("parse direnv status json");
        let n: &f64 = v["state"]["foundRC"]["allowed"].get().expect("foundRC.allowed");
        *n as u8
    }

    #[test]
    fn native_matches_direnv_status() {
        let raw = std::env::temp_dir().join(format!("di-allowtest-{}", std::process::id()));
        let _ = fs::remove_dir_all(&raw);
        fs::create_dir_all(&raw).unwrap();
        fs::write(raw.join(".envrc"), "export DI_ALLOWTEST=1\n").unwrap();
        // canonicalize so our path matches the one direnv keys on (temp_dir is a symlink on macOS)
        let dir = fs::canonicalize(&raw).unwrap();

        for sub in ["", "allow", "deny"] {
            if !sub.is_empty() {
                direnv(&dir, sub);
            }
            assert_eq!(allow_state(&dir), status_found_allowed(&dir), "state after `{sub}`");
        }

        let _ = fs::remove_dir_all(&dir);
    }
}
