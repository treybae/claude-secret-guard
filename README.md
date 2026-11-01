<p align="center">
  <img src=".claude-plugin/icon.png" alt="secret-guard: a pixel-art three-headed dog standing guard on a gold key" width="256">
</p>

# secret-guard

An SRE's shell holds the keys to production: Vault tokens, AWS profiles, kubeconfigs, API keys in dotfiles. Claude Code's auto mode makes agents fast because they act without asking, but that also means one stray `cat ~/.zshrc` or `vault kv get` can put a live credential into an AI transcript. Turning auto mode off is safe but slow. secret-guard gives you both: it blocks commands and file reads that expose credentials, redacts secrets from anything a tool returns before Claude sees it, and logs what it did in `/secret-guard`. Install it once, keep auto mode on.

It does four things, in every permission mode, including auto and inside subagents:

1. **Blocks shell commands that touch credential files.** Any command that mentions `~/.zshrc`, `~/.zprofile`, `~/.zshenv`, `~/.zlogin`, `~/.bashrc`, `~/.bash_profile`, `~/.profile`, `~/.netrc`, `~/.vault-token`, `~/.git-credentials`, `~/.npmrc`, `~/.pypirc`, `~/.terraformrc`, `~/.terraform.d/credentials.tfrc.json`, `~/.docker/config.json`, or anything in `~/.aws`, `~/.ssh`, `~/.kube`, `~/.gnupg`, `~/.azure`, `~/.config/op`, `~/.config/gh` or `~/.config/gcloud`. That includes `$HOME/...`, absolute paths, and relative spellings after `cd ~`.
2. **Blocks environment dumps and commands that print secrets.** `env`, `printenv`, `export -p`, `declare -x` and a bare `set`, plus:
    - `op read`, `op item get --reveal`, `op run --no-masking`
    - `vault read`, `vault kv get`, `vault token lookup` / `create`, `vault print token`, `vault login`
    - `aws configure get` / `export-credentials`, `aws sts get-session-token`, `aws ecr get-login-password` on its own, `aws secretsmanager get-secret-value`, `aws ssm get-parameter --with-decryption`
    - `gh auth token`, `gh auth status --show-token`
    - `kubectl get secret … -o yaml|json|jsonpath|go-template`
    - `security find-generic-password -w`, `gcloud auth print-access-token`, `az account get-access-token`, `git credential fill`

    `set -euo pipefail`, `env FOO=bar cmd`, `kubectl get secrets`, `vault status`, `aws sts get-caller-identity` and `op run -- cmd` still work.
3. **Blocks file tools** (Read, Grep, Glob, Edit, Write) on the credential files in item 1.
4. **Redacts secrets from tool output.** Whatever a tool returns, these are replaced with `[REDACTED by secret-guard]` before Claude reads it:
    - anything shaped like a Vault, GitHub, AWS, Slack, 1Password, Anthropic, Stripe or Google key or token, a JWT, or a private key block
    - values of `password`, `secret`, `token`, `api_key`, `app_key` and similar assignments, including Datadog `DD_API_KEY` / `DD_APP_KEY` and AWS `SecretAccessKey` / `SessionToken` JSON
    - key headers: `DD-API-KEY`, `DD-APPLICATION-KEY`, `X-API-Key`, `Authorization`
    - the values under `data:` and `stringData:` in Kubernetes Secret YAML, including multi-line `|` values

    This catches what slips past the blocks. Placeholders (`$TOKEN`, `<value>`, `op://...`) and SOPS-encrypted values (`ENC[...]`) are left alone. When something is redacted or blocked, the status line says so briefly, for example `secret-guard: redacted 3 secrets · /secret-guard for details`, and clears when you send your next prompt. `/secret-guard` has the details.

**`/secret-guard`** shows this session's log, newest first: each redaction with the tool and command or file it came from, the kinds found, and the affected lines with the values already replaced; and each block or approval prompt with the command and the reason. `/secret-guard clear` empties it. The log holds no secret values, and it starts empty in each session.

```
1.  09:42:07  redacted 1 secret from Bash output
    where: Bash `make debug`
    what:  Vault token
    lines: VAULT_TOKEN=[REDACTED by secret-guard]
2.  09:41:55  blocked: Bash `tail ~/.zshrc`
    why:   this command references a shell config or credential file (~/.zshrc, ~/.aws, ~/.ssh, ~/.vault-token, ...)
```

**Blocks unsafe heredocs.** A shell heredoc ends at the first line matching its marker, so text that contains its own marker ends it early and the rest runs as shell commands. secret-guard blocks:

- heredocs that write a file (`cat > file <<EOF`, `cat >> file <<EOF`, `tee file <<EOF`). Claude uses the Write tool instead, which writes text exactly as given.
- any heredoc whose marker also appears inside its own text, even one that only feeds a command.

Heredocs that feed a command and end correctly still work: `kubectl apply -f - <<EOF`, `psql <<SQL`, `python - <<PY`, and commit messages written with `git commit -m "$(cat <<'EOF' … EOF)"`.

**Asks before a few borderline commands.** These are often legitimate, so instead of refusing them, secret-guard asks you to **Allow once** or **Block**:

- passing your kubeconfig to a tool: `kubectl --kubeconfig ~/.kube/config …`, `KUBECONFIG=~/.kube/… helm …`
- `aws ecr get-login-password` piped straight into `docker`, `podman`, `helm`, `crane`, `oras` or `skopeo` with `--password-stdin`
- `aws sts assume-role`, whose temporary credentials are redacted from the output

Anything else in the same command still blocks. If the dialog is dismissed, or no one can answer (`claude -p`), the command is blocked.

A blocked call comes back to Claude with the reason, so it asks you instead of retrying. If you need the output yourself, run the command in a separate terminal, **not** with `!` at the Claude prompt: anything run with `!` goes into the conversation, where secret-guard can't redact it.

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
- **Some legitimate commands are refused**, such as `vault kv get` when you really need the value. Run those in a separate terminal.
- **Kubernetes Secret redaction reads YAML only.** JSON output (`kubectl get secret -o json`) is blocked as a command instead.

## Tests

`claude plugin test .` runs the checks in `hooks/secret-guard.test.ts`: 57 commands that must be blocked, 29 that must pass, the borderline commands that ask, file paths both ways, each token shape, Datadog and AWS credentials, Kubernetes Secret manifests, placeholders and ordinary output left alone, and end-to-end calls for blocking, asking (allowed, blocked, no answer) and redaction.
