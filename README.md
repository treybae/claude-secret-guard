# secret-guard

Stops Claude Code from reading shell config, credential files or the environment, so secrets don't end up in a transcript. It replaces hand-editing `~/.claude/settings.json` with deny rules and a hook script.

It does two things, in every permission mode, including auto and inside subagents:

1. **Blocks shell commands** that mention `~/.zshrc`, `~/.zprofile`, `~/.zshenv`, `~/.zlogin`, `~/.bashrc`, `~/.bash_profile`, `~/.profile`, `~/.netrc`, `~/.aws`, `~/.ssh`, `~/.config/op`, `~/.docker/config.json` or `~/.kube/config`. That includes `$HOME/...`, absolute paths, and relative spellings after `cd ~`. It also blocks commands that dump the environment: `env`, `printenv`, `export -p`, `declare -x` and a bare `set`. `set -euo pipefail` and `env FOO=bar cmd` still work.
2. **Blocks file tools** (Read, Grep, Glob, Edit, Write) on those same files.

Pair it with a written rule in your `~/.claude/CLAUDE.md`, so Claude avoids secrets on purpose and passes that on to subagents:

```markdown
## Secrets

- Never read, grep, tail or print shell config or credential files: ~/.zshrc, ~/.zprofile,
  ~/.bashrc, ~/.profile, ~/.netrc, ~/.aws/, ~/.ssh/, ~/.kube/config, ~/.config/op/,
  ~/.docker/config.json.
- Never dump the environment: env, printenv, set, export -p, declare -x.
- Write files with the Write and Edit tools, never shell heredocs.
- If a task seems to need a secret or a config value, ask me.
- Copy these rules into the brief of every subagent you start.
```

A blocked call comes back to Claude with the reason, so it asks you instead of retrying.

## Install

In a Claude Code terminal session:

```
/plugin install secret-guard --marketplace treybae/claude-secret-guard
```

Answer `y` to add the marketplace, then press Enter to install at the user scope. From a shell:

```sh
claude plugin install secret-guard --marketplace treybae/claude-secret-guard
```

In the desktop app, click + next to the prompt box, then **Plugins**, **Add marketplace** with `treybae/claude-secret-guard`, then **Add plugin**.

## Limits

It matches text, so a path built at run time (`cat "$(echo ~)/.zsh""rc"`) or a script that opens the file itself gets through. Keep secrets out of plain-text files, in 1Password with `op run`, as the real fix. Some legitimate commands are refused, such as `kubectl --kubeconfig ~/.kube/config`. Drop the explicit path or run it yourself with `!`.

## Tests

`claude plugin test .` runs the checks in `hooks/secret-guard.test.ts`: 20 commands that must be blocked, 16 that must pass, file paths both ways, and two end-to-end calls.
