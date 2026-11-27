//! Shell completions: the flags, then whatever you'd complete after `sudo`.
pub const FISH: &str = r#"# agent-sudo and asudo
complete -c agent-sudo -s h -l help -d "Show help"
complete -c agent-sudo -s v -l version -d "Show the version"
complete -c agent-sudo -s s -l status -d "Check the installation"
complete -c agent-sudo -s l -l logs -d "Show the last audit log entries"
complete -c agent-sudo -s c -l check -d "Check a command against the guardrails without running it"
complete -c agent-sudo -s e -l explain -d "Say why a command would be blocked, or allowed"
complete -c agent-sudo -s r -l rules -d "List the guardrail rules"
complete -c agent-sudo -l install -d "Install (needs root)"
complete -c agent-sudo -l uninstall -d "Remove everything agent-sudo installed (needs root)"
complete -c agent-sudo -l completions -x -a "fish bash zsh" -d "Print completions for a shell"
complete -c agent-sudo -a "(__fish_complete_subcommand)"
complete -c asudo -w agent-sudo
"#;

pub const BASH: &str = r#"# agent-sudo and asudo
_agent_sudo() {
    local cur=${COMP_WORDS[COMP_CWORD]}
    if [[ $COMP_CWORD -eq 1 && $cur == -* ]]; then
        COMPREPLY=( $(compgen -W "-h --help -v --version -s --status -l --logs -c --check -e --explain -r --rules --install --uninstall --completions" -- "$cur") )
    elif declare -F _command_offset >/dev/null; then
        _command_offset 1
    else
        COMPREPLY=( $(compgen -c -- "$cur") )
    fi
}
complete -F _agent_sudo agent-sudo asudo
"#;

pub const ZSH: &str = r#"#compdef agent-sudo asudo
_arguments -s \
  '(- *)'{-h,--help}'[show help]' \
  '(- *)'{-v,--version}'[show the version]' \
  '(- *)'{-s,--status}'[check the installation]' \
  '(- *)'{-l,--logs}'[show the last audit log entries]::count:' \
  '(- *)'{-c,--check}'[check a command against the guardrails]:*::command:_normal' \
  '(- *)'{-e,--explain}'[say why a command would be blocked or allowed]:*::command:_normal' \
  '(- *)'{-r,--rules}'[list the guardrail rules]' \
  '(- *)--install[install (needs root)]' \
  '(- *)--uninstall[remove everything agent-sudo installed (needs root)]' \
  '(- *)--completions[print completions]:shell:(fish bash zsh)' \
  '*::command:_normal'
"#;

pub fn for_shell(shell: &str) -> Option<&'static str> {
    match shell {
        "fish" => Some(FISH),
        "bash" => Some(BASH),
        "zsh" => Some(ZSH),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_flag_is_in_every_script() {
        for (shell, text) in [("fish", FISH), ("bash", BASH), ("zsh", ZSH)] {
            for flag in ["help", "version", "status", "logs", "check", "explain", "rules", "install", "uninstall", "completions"] {
                assert!(text.contains(flag), "{shell} lacks {flag}");
            }
            assert!(text.contains("asudo"), "{shell} doesn't cover asudo");
        }
        assert!(for_shell("fish").is_some() && for_shell("tcsh").is_none());
    }
}
