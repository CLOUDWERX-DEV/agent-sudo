//! `/etc/agent-sudo.json`, the administrator's policy. Optional. Read by the root side only, and only if root owns it and nobody else can write to it.
//!
//! ```json
//! { "allow_programs": ["pacman", "systemctl"], "deny_programs": ["curl"], "disable_rules": ["power"], "notify": true }
//! ```
//! Unknown keys and unknown rule names are errors, not ignored: a typo in `allow_programs` must never quietly mean "allow everything".
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use serde_json::Value;

use crate::guard::{Policy, RULES};

pub const CONFIG_PATH: &str = "/etc/agent-sudo.json";

#[derive(Debug, Clone)]
pub struct Config {
    pub policy: Policy,
    pub notify: bool,
}

impl Default for Config {
    fn default() -> Config {
        Config { policy: Policy::default(), notify: true }
    }
}

fn strings(v: &Value, key: &str) -> Result<Vec<String>, String> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(vec![]),
        Some(Value::Array(a)) => a.iter().map(|x| x.as_str().map(String::from).ok_or_else(|| format!("{key} must be a list of strings"))).collect(),
        Some(_) => Err(format!("{key} must be a list of strings")),
    }
}

pub fn parse(text: &str) -> Result<Config, String> {
    let v: Value = serde_json::from_str(text).map_err(|e| format!("not valid JSON: {e}"))?;
    let obj = v.as_object().ok_or("the top level must be an object")?;
    for k in obj.keys() {
        if !["allow_programs", "deny_programs", "disable_rules", "notify"].contains(&k.as_str()) {
            return Err(format!("unknown key '{k}' (known: allow_programs, deny_programs, disable_rules, notify)"));
        }
    }
    let disabled = strings(&v, "disable_rules")?;
    if let Some(bad) = disabled.iter().find(|r| !RULES.iter().any(|(n, _)| n == r)) {
        return Err(format!("unknown rule '{bad}' in disable_rules (see `agent-sudo --rules`)"));
    }
    let notify = match v.get("notify") {
        None | Some(Value::Null) => true,
        Some(Value::Bool(b)) => *b,
        Some(_) => return Err("notify must be true or false".into()),
    };
    Ok(Config { policy: Policy { disabled: disabled.into_iter().collect(), allow_programs: strings(&v, "allow_programs")?, deny_programs: strings(&v, "deny_programs")? }, notify })
}

/// Load the config from `path`: the defaults if it isn't there, an error if it's unsafe or broken. Refusing is deliberate: a policy that is
/// ignored because of a typo or a bad permission would silently be looser than the administrator meant.
pub fn load_checked(path: &Path) -> Result<Config, String> {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Config::default()),
        Err(e) => return Err(format!("can't read {}: {e}", path.display())),
    };
    if meta.uid() != 0 || meta.mode() & 0o022 != 0 {
        return Err(format!("{} must be owned by root and not writable by anyone else (chown root:root, chmod 644)", path.display()));
    }
    parse(&std::fs::read_to_string(path).map_err(|e| e.to_string())?).map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_everything() {
        let c = parse(r#"{"allow_programs":["pacman"],"deny_programs":["curl"],"disable_rules":["power"],"notify":false}"#).unwrap();
        assert_eq!(c.policy.allow_programs, vec!["pacman"]);
        assert_eq!(c.policy.deny_programs, vec!["curl"]);
        assert!(c.policy.disabled.contains("power") && !c.notify);
        let d = parse("{}").unwrap();
        assert!(d.notify && d.policy.allow_programs.is_empty());
    }

    #[test]
    fn typos_are_errors_not_silence() {
        assert!(parse(r#"{"allow_program":["pacman"]}"#).unwrap_err().contains("unknown key"));
        assert!(parse(r#"{"disable_rules":["powr"]}"#).unwrap_err().contains("unknown rule"));
        assert!(parse(r#"{"allow_programs":"pacman"}"#).is_err());
        assert!(parse(r#"{"notify":"yes"}"#).is_err());
        assert!(parse("[]").is_err());
        assert!(parse("nope").is_err());
    }

    #[test]
    fn a_missing_file_is_the_defaults_and_an_unsafe_one_is_refused() {
        let dir = std::env::temp_dir().join(format!("agent-sudo-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(load_checked(&dir.join("none.json")).unwrap().notify);
        let f = dir.join("c.json");
        std::fs::write(&f, "{}").unwrap();
        // owned by the test user, not root: refused when the user isn't root
        if unsafe { libc::geteuid() } != 0 {
            assert!(load_checked(&f).unwrap_err().contains("owned by root"));
        }
    }
}
