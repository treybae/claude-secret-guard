# secret-guard

Stops Claude Code from reading credential files, dumping the environment or printing secrets, and redacts secrets from anything a tool returns, so they don't end up in a transcript. It replaces hand-editing `~/.claude/settings.json` with deny rules and a hook script.

It does four things, in every permission mode, including auto and inside subagents:

1. **Blocks shell commands that touch credential files.** Any command that mentions `~/.zshrc`, `~/.zprofile`, `~/.zshenv`, `~/.zlogin`, `~/.bashrc`, `~/.bash_profile`, `~/.profile`, `~/.netrc`, `~/.vault-token`, `~/.git-credentials`, `~/.npmrc`, `~/.pypirc`, `~/.terraformrc`, `~/.terraform.d/credentials.tfrc.json`, `~/.docker/config.json`, or anything in `~/.aws`, `~/.ssh`, `~/.kube`, `~/.gnupg`, `~/.azure`, `~/.config/op`, `~/.config/gh` or `~/.config/gcloud`. That includes `$HOME/...`, absolute paths, and relative spellings after `cd ~`.
2. **Blocks environment dumps and commands that print secrets.** `env`, `printenv`, `export -p`, `declare -x` and a bare `set`, plus:
    - `op read`, `op item get --reveal`, `op run --no-masking`
    - `vault read`, `vault kv get`, `vault token lookup` / `create`, `vault print token`, `vault login`
    - `aws configure get` / `export-credentials`, `aws sts get-session-token` / `assume-role`, `aws ecr get-login-password`, `aws secretsmanager get-secret-value`, `aws ssm get-parameter --with-decryption`
    - `gh auth token`, `gh auth status --show-token`
    - `kubectl get secret … -o yaml|json|jsonpath|go-template`
    - `security find-generic-password -w`, `gcloud auth print-access-token`, `az account get-access-token`, `git credential fill`

    `set -euo pipefail`, `env FOO=bar cmd`, `kubectl get secrets`, `vault status`, `aws sts get-caller-identity` and `op run -- cmd` still work.
3. **Blocks file tools** (Read, Grep, Glob, Edit, Write) on the credential files in item 1.
4. **Redacts secrets from tool output.** Whatever a tool returns, anything shaped like a Vault, GitHub, AWS, Slack, 1Password, Anthropic, Stripe or Google key or token, a JWT, a private key block, or a `password`/`secret`/`token`/`api_key` assignment is replaced with `[REDACTED by secret-guard]` before Claude reads it. This catches what slips past the blocks. Placeholders such as `$TOKEN`, `<value>` and `op://...` are left alone.

A blocked call comes back to Claude with the reason, so it asks you instead of retrying. To run a blocked command yourself, type it with `!` at the prompt.

Pair it with a written rule in your `~/.claude/CLAUDE.md`, so Claude avoids secrets on purpose and passes that on to subagents:

```markdown
## Secrets

- Never read, grep, tail or print shell config or credential files: ~/.zshrc, ~/.zprofile,
  ~/.bashrc, ~/.profile, ~/.netrc, ~/.vault-token, ~/.aws/, ~/.ssh/, ~/.kube/, ~/.config/op/,
  ~/.docker/config.json.
- Never dump the environment: env, printenv, set, export -p, declare -x.
- Never run commands that print secrets (op read, vault kv get, kubectl get secret -o yaml, ...).
- Write files with the Write and Edit tools, never shell heredocs.
- If a task seems to need a secret or a config value, ask me.
- Copy these rules into the brief of every subagent you start.
```

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

- **Blocks match text.** A path built at run time (`cat "$(echo ~)/.zsh""rc"`) or a script that opens the file itself gets past the blocks. Redaction catches known token shapes in the output, but not every secret has a recognizable shape. Keep secrets out of plain-text files, in 1Password with `op run`, as the real fix.
- **Redaction changes what Claude sees.** Test fixtures or docs that contain token-shaped strings are redacted too.
- **Some legitimate commands are refused**, such as `kubectl --kubeconfig ~/.kube/config` or `vault kv get` when you really need the value. Drop the explicit path, or run it yourself with `!`.

## Tests

`claude plugin test .` runs the checks in `hooks/secret-guard.test.ts`: 58 commands that must be blocked, 29 that must pass, file paths both ways, each token shape, placeholders and ordinary output left alone, and end-to-end calls for blocking and redaction.
