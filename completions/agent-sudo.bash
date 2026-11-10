# Bash completion for agent-sudo

_agent_sudo() {
  local cur prev
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"

  if [ "${COMP_CWORD}" -eq 1 ]; then
    case "${cur}" in
      -*)
        COMPREPLY=( $(compgen -W "-h --help -v --version -s --status -l --logs" -- "${cur}") )
        return 0
        ;;
      *)
        COMPREPLY=( $(compgen -c -- "${cur}") )
        return 0
        ;;
    esac
  fi

  # Fallback to standard command completion
  _command_offset 1
}

complete -F _agent_sudo agent-sudo
complete -F _agent_sudo asudo
