# Fish completion for agent-sudo and asudo

# Command options
complete -c agent-sudo -s h -l help -d "Show help and usage"
complete -c agent-sudo -s v -l version -d "Show version"
complete -c agent-sudo -s s -l status -d "Check installation health and sudoers"
complete -c agent-sudo -s l -l logs -d "View recent audit logs"

# Inherit command completions (allows completing pacman, systemctl, etc. after agent-sudo)
complete -c agent-sudo -a "(__fish_complete_subcommand)"

# Shorthand alias completions
complete -c asudo -w agent-sudo
