# Changelog

## 0.5.0

- Team settings: `extra_paths` adds files or folders to protect, and `extra_commands` adds regular expressions for commands that print secrets. Set them in `/config` or under `pluginConfigs` in `settings.json`.
- Switches to turn off each rule on its own, all on by default: `block_credential_files`, `block_env_dumps`, `block_secret_commands`, `block_heredocs`, `ask_borderline` and `redact_output`.
- `allow_commands`: regular expressions for shell commands that are never blocked. Each must match the whole command; their output is still redacted.
- Invalid entries are skipped with a warning. `/secret-guard` lists the rules that are off and how many extras and allowed commands are active.
- Self-protection, always on: Claude can't edit settings files in ways that touch secret-guard, `enabledPlugins`, `pluginConfigs` or `disableAllHooks`, run `claude plugin disable` or `uninstall` on it, or change its installed files.

## 0.4.2

- New plugin description: "Your shell holds the keys to production. secret-guard stops Claude Code from reading, printing or leaking them."

## 0.4.1

- Shorter status line: `redacted 8 secrets · /secret-guard for details`, `blocked a command · …`, `blocked an unsafe heredoc · …`. The kinds, sources and reasons are in `/secret-guard`. The text no longer repeats the plugin's name, which Claude Code already shows.

## 0.4.0

- Blocks heredocs that write a file (`cat > file <<EOF`, `tee file <<EOF`) and points Claude to the Write tool, which can't run any of the text it writes.
- Blocks any heredoc whose marker also appears inside its own text, so it would end early and run the rest as shell commands. This was the root cause of the leak that started this plugin.
- Heredocs that feed a command and end correctly (`kubectl apply -f - <<EOF`, `git commit -m "$(cat <<'EOF' … EOF)"`) still work.

## 0.3.0

- `/secret-guard` shows this session's log, newest first: each redaction with the tool, command or file, the kinds of secret found and the affected lines with values replaced; each block or approval prompt with its reason. `/secret-guard clear` empties it.
- Blocked commands now set the status line too, and every status line points to `/secret-guard`.

## 0.2.2

- The status line names what was redacted (kinds only, never values), for example `Vault token, DD_API_KEY value ×2`.
- The status line clears when you send your next prompt.

## 0.2.1

- Block messages no longer suggest running the command with `!`, since that puts its output into the conversation unredacted. They say to use a separate terminal.
- Asks with **Allow once** or **Block** before a few borderline commands: passing a kubeconfig with `--kubeconfig` or `KUBECONFIG=`, `aws ecr get-login-password` piped into a `--password-stdin` login, and `aws sts assume-role`.
- Redacts Datadog keys (`DD_API_KEY`, `DD_APP_KEY`, `DD-API-KEY` and `DD-APPLICATION-KEY` headers), `X-API-Key` and `Authorization` headers, AWS `SecretAccessKey` and `SessionToken` JSON, and the values in Kubernetes Secret YAML. SOPS-encrypted values are left alone.

## 0.2.0

- Redacts secrets from every tool's output before Claude reads it: Vault, GitHub, AWS, Slack, 1Password, Anthropic, Stripe and Google keys and tokens, JWTs, private keys, and `password`, `secret`, `token` and `api_key` values.
- Blocks commands that print secrets: `op read`, `vault kv get`, `aws configure get`, `gh auth token`, `kubectl get secret -o yaml` and others.
- Covers more credential files: `~/.vault-token`, `~/.config/gh`, `~/.git-credentials`, `~/.npmrc`, `~/.pypirc`, Terraform credentials, `~/.config/gcloud`, `~/.azure`, `~/.gnupg` and all of `~/.kube`.

## 0.1.0

- Blocks shell commands that reference shell config or credential files, including relative paths after `cd ~`, and commands that dump the environment.
- Blocks file tools (Read, Grep, Glob, Edit, Write) on those files.
