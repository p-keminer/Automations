# Bash completion for installed Automations commands; never execute modules.
_auto_complete() {
    local cur="${COMP_WORDS[COMP_CWORD]-}" prev cword="$COMP_CWORD"
    local prefix="" colon_prefix="" index
    local -a words=("${COMP_WORDS[@]}")
    COMPREPLY=()
    # Readline splits '=' and ':' before invoking us. Reassemble only this
    # completion context, without changing other commands' COMP_WORDBREAKS.
    # A directly sourced wrapper also keeps working without bash-completion.
    if declare -F _get_comp_words_by_ref >/dev/null; then
        _get_comp_words_by_ref -n =: cur prev words cword || return 0
        words[cword]="$cur"
    fi
    mapfile -t COMPREPLY < <(/usr/bin/python3 \
        /usr/local/libexec/automations-support/completion.py \
        "$cword" "${words[@]}" 2>/dev/null)
    # The reader returns whole logical words; Readline replaces only the text
    # after the last active word break. Strip that prefix to avoid duplicates.
    if [[ "$COMP_WORDBREAKS" == *=* && "$cur" == *=* ]]; then
        prefix="${cur%"${cur##*=}"}"
    fi
    if [[ "$COMP_WORDBREAKS" == *:* && "$cur" == *:* ]]; then
        colon_prefix="${cur%"${cur##*:}"}"
        (( ${#colon_prefix} > ${#prefix} )) && prefix="$colon_prefix"
    fi
    if [[ -n "$prefix" ]]; then
        for index in "${!COMPREPLY[@]}"; do
            COMPREPLY[index]="${COMPREPLY[index]#"$prefix"}"
        done
    fi
    return 0
}
complete -F _auto_complete auto
