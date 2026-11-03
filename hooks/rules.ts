// Pure checks shared by the hooks and the tests.

// Files that hold credentials, by their name under the home folder.
const HOME_FILES = 'zshrc|zprofile|zshenv|zlogin|bashrc|bash_profile|profile|netrc|vault-token|git-credentials|npmrc|pypirc|terraformrc'
// Folders under the home folder whose contents are credentials.
const HOME_DIRS = 'aws|ssh|kube|gnupg|azure|config/op|config/gh|config/gcloud'
// Single files deeper under the home folder.
const HOME_NESTED = String.raw`\.docker/config\.json|\.terraform\.d/credentials\.tfrc\.json`

// The same files spelled relative to ~ (after `cd ~`). `.npmrc`, `.pypirc` and `.terraformrc` are
// left out here: projects keep their own copies, which hold no credentials.
const BARE_FILES = 'zshrc|zprofile|zshenv|zlogin|bashrc|bash_profile|profile|netrc|vault-token|git-credentials'
const BARE_DIRS = 'aws|ssh|kube|gnupg|azure'

const HOME = String.raw`(?:~|\$HOME|\$\{HOME\}|/Users/[^/\s]+|/home/[^/\s]+)`
const END = String.raw`(?=[\s"';|&)]|$)`
const DIR_END = String.raw`(?=/|[\s"';|&)]|$)`

const HOME_PATH = new RegExp(`${HOME}/(?:\\.(?:${HOME_FILES})${END}|\\.(?:${HOME_DIRS})${DIR_END}|${HOME_NESTED})`)
const BARE_NAME = new RegExp(`(?:^|[\\s/"'=])\\.(?:${BARE_FILES})${END}|(?:^|[\\s"'=])\\.(?:${BARE_DIRS})${DIR_END}`)

// Bare env/printenv (or printenv NAME), export -p, declare -x, and a bare `set` print the environment.
// `env FOO=bar cmd` and `set -euo pipefail` stay allowed.
const ENV_DUMP = new RegExp(
  String.raw`(?:^|[;&|(` + '`' + String.raw`]|\$\()\s*(?:env|printenv)(?:\s*(?:$|[;&|)` + '`' + String.raw`>])|\s+[A-Za-z_]*(?:$|[;&|)` + '`' + String.raw`>]))` +
    String.raw`|(?:^|[;&|(]|\$\()\s*(?:export\s+-p|declare\s+-x|set)\s*(?:$|[;&|)>])`,
)

// CLI commands whose job is to print a secret. `[^|;&]*` lets flags sit between the parts of one command.
const SECRET_COMMANDS: readonly [RegExp, string][] = [
  [/\bop\s+read\b/, '`op read` prints a 1Password secret'],
  [/\bop\s+item\s+get\b[^|;&]*--reveal\b/, '`op item get --reveal` prints 1Password secrets'],
  [/\bop\s+run\b[^|;&]*--no-masking\b/, '`op run --no-masking` prints secrets unmasked'],
  [/\bvault\b[^|;&]*\s(?:read|kv\s+get|token\s+(?:lookup|create)|print\s+token|login)\b/, 'this vault command prints a secret or token'],
  [
    /\baws\b[^|;&]*\s(?:configure\s+(?:get|export-credentials)|sts\s+get-session-token|ecr\s+get-login-password|secretsmanager\s+get-secret-value|ssm\s+get-parameters?\b[^|;&]*--with-decryption)\b/,
    'this aws command prints credentials or a secret',
  ],
  [/\bgh\s+auth\s+(?:token\b|status\b[^|;&]*(?:-t\b|--show-token\b))/, 'this gh command prints a GitHub token'],
  [
    /\bkubectl\b[^|;&]*\bget\s+secrets?\b[^|;&]*(?:-o\s*|--output[=\s]+)(?:yaml|json|jsonpath|go-template)/,
    '`kubectl get secret -o …` prints secret values',
  ],
  [/\bkubectl\b[^|;&]*\bget\s+secrets?\/[^|;&]*(?:-o\s*|--output[=\s]+)(?:yaml|json|jsonpath|go-template)/, '`kubectl get secret -o …` prints secret values'],
  [/\bsecurity\s+find-(?:generic|internet)-password\b[^|;&]*\s-[wg]\b/, 'this keychain command prints a password'],
  [/\bgcloud\s+auth\s+print-(?:access|identity)-token\b/, 'this gcloud command prints a token'],
  [/\baz\s+account\s+get-access-token\b/, 'this az command prints a token'],
  [/\bgit\s+credential\s+fill\b/, '`git credential fill` prints a stored credential'],
]

// A heredoc opener: `<<EOF`, `<<-EOF`, `<<'EOF'`, `<< "EOF"`. A herestring (`<<<`) is not one.
const HEREDOC_OPEN = /(?<!<)<<(-?)\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\2/g
// On a heredoc's opening line: `cat` redirected into a file, or `tee` naming one. Redirects to
// another stream (`>&2`) or to /dev/null, /dev/stdout and /dev/stderr don't write a file.
const CAT_TO_FILE = /\bcat\b[^|;&]*?(?<![0-9&])>{1,2}\s*(?!&|\/dev\/(?:null|stdout|stderr)\b)["']?[^\s"'&|;<>]/
const TEE_TO_FILE = /\btee\b(?:\s+-[a-z]+)*\s+(?!\/dev\/(?:null|stdout|stderr)\b)["']?[^\s"'&|;<>-]/

/**
 * Why a command's heredocs are unsafe, or undefined when they're fine:
 * a heredoc that writes a file (use the Write tool), or one whose marker also appears inside
 * its own text, so it ends early and the rest of the text runs as shell commands.
 */
export function heredocReason(command: string): string | undefined {
  const lines = command.split('\n')
  const pending: { marker: string; tabs: boolean }[] = []
  const closed = new Set<string>()
  for (const line of lines) {
    const open = pending[0]
    if (open) {
      if ((open.tabs ? line.replace(/^\t+/, '') : line) === open.marker) {
        closed.add(open.marker)
        pending.shift()
      }
      continue
    }
    // A command line on its own that is just a used-up marker: an earlier heredoc ended early,
    // and this line (and everything before it since then) would run as commands.
    if (closed.has(line.trim()) && /^\s*[A-Za-z_][A-Za-z0-9_]*\s*$/.test(line)) {
      return `this heredoc ends early: its marker \`${line.trim()}\` also appears inside its own text, so the rest of that text would run as shell commands. Use a marker that doesn't appear in the text, or write files with the Write tool`
    }
    HEREDOC_OPEN.lastIndex = 0
    const opened = [...line.matchAll(HEREDOC_OPEN)]
    if (opened.length && (CAT_TO_FILE.test(line) || TEE_TO_FILE.test(line))) {
      return 'this command writes a file through a heredoc. Use the Write tool instead: it writes the text exactly as given, while a heredoc can end early and run its text as shell commands'
    }
    for (const m of opened) pending.push({ marker: m[3]!, tabs: m[1] === '-' })
  }
  return undefined
}

/** The switches in the plugin's settings. Each is on unless the setting is false. */
export type Rules = {
  readonly credentialFiles: boolean
  readonly envDumps: boolean
  readonly secretCommands: boolean
  readonly heredocs: boolean
  readonly askBorderline: boolean
  readonly redactOutput: boolean
}

/** Each switch with its setting name and how /secret-guard names it. */
export const RULE_SETTINGS: readonly [keyof Rules, string, string][] = [
  ['credentialFiles', 'block_credential_files', 'credential file blocks'],
  ['envDumps', 'block_env_dumps', 'environment dump blocks'],
  ['secretCommands', 'block_secret_commands', 'secret-printing command blocks'],
  ['heredocs', 'block_heredocs', 'heredoc blocks'],
  ['askBorderline', 'ask_borderline', 'asking before borderline commands'],
  ['redactOutput', 'redact_output', 'output redaction'],
]

const ALL_ON: Rules = { credentialFiles: true, envDumps: true, secretCommands: true, heredocs: true, askBorderline: true, redactOutput: true }

/** What a team sets in the plugin's settings, compiled. */
export type Extras = {
  /** Match an extra path inside a shell command. */
  readonly commandPaths: readonly RegExp[]
  /** Match an extra path as a file tool receives it. */
  readonly filePaths: readonly RegExp[]
  /** Extra commands that print secrets, each with the pattern as given, for the reason. */
  readonly commands: readonly [RegExp, string][]
  /** Commands that are never blocked, each anchored to match the whole command. */
  readonly allow: readonly RegExp[]
  /** Which rules are on. */
  readonly rules: Rules
  /** Entries that couldn't be used, for a warning. */
  readonly problems: readonly string[]
}

export const NO_EXTRAS: Extras = { commandPaths: [], filePaths: [], commands: [], allow: [], rules: ALL_ON, problems: [] }

// A switch is off only when set to false (or the text "false").
const isOff = (value: unknown) => value === false || (typeof value === 'string' && value.trim().toLowerCase() === 'false')

const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

function list(value: unknown): string[] {
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === 'string')
  // A single string is read as one entry per line or comma.
  if (typeof value === 'string') return value.split(/[\n,]/)
  return []
}

/** Compile the plugin's `extra_paths` and `extra_commands` settings. Bad entries are reported, not fatal. */
export function compileExtras(options: Readonly<Record<string, unknown>>): Extras {
  const commandPaths: RegExp[] = []
  const filePaths: RegExp[] = []
  const commands: [RegExp, string][] = []
  const problems: string[] = []

  for (const raw of list(options['extra_paths'])) {
    const p = raw.trim().replace(/\/+$/, '')
    if (!p) continue
    if (p.startsWith('~/') && p.length > 2) {
      const rel = escape(p.slice(2))
      commandPaths.push(new RegExp(`${HOME}/${rel}${DIR_END}`))
      filePaths.push(new RegExp(String.raw`^(?:~|/Users/[^/]+|/home/[^/]+|/root)/` + `${rel}(?:/|$)`))
    } else if (p.startsWith('/') && p.length > 1) {
      commandPaths.push(new RegExp(`${escape(p)}${DIR_END}`))
      filePaths.push(new RegExp(`^${escape(p)}(?:/|$)`))
    } else {
      problems.push(`extra_paths entry "${p}" must start with ~/ or /`)
    }
  }

  for (const raw of list(options['extra_commands'])) {
    const pattern = raw.trim()
    if (!pattern) continue
    try {
      commands.push([new RegExp(pattern), pattern])
    } catch {
      problems.push(`extra_commands entry "${pattern}" is not a valid regular expression`)
    }
  }

  const allow: RegExp[] = []
  for (const raw of list(options['allow_commands'])) {
    const pattern = raw.trim()
    if (!pattern) continue
    try {
      allow.push(new RegExp(`^(?:${pattern})$`))
    } catch {
      problems.push(`allow_commands entry "${pattern}" is not a valid regular expression`)
    }
  }

  const rules = Object.fromEntries(RULE_SETTINGS.map(([key, setting]) => [key, !isOff(options[setting])])) as Rules

  return { commandPaths, filePaths, commands, allow, rules, problems }
}

/** Why a shell command must not run, or undefined when it may. */
export function bashReason(command: string, extras: Extras = NO_EXTRAS): string | undefined {
  const { rules } = extras
  if (rules.credentialFiles && (HOME_PATH.test(command) || BARE_NAME.test(command))) {
    return 'this command references a shell config or credential file (~/.zshrc, ~/.aws, ~/.ssh, ~/.vault-token, ...)'
  }
  // The team's own additions stay on whatever the switches say: to stop one, remove it.
  if (extras.commandPaths.some(re => re.test(command))) return 'this command references a path your team protects in secret-guard settings'
  if (rules.envDumps && ENV_DUMP.test(command)) return 'this command prints environment variables, which may hold secrets'
  const extra = extras.commands.find(([re]) => re.test(command))
  if (extra) return `this command matches \`${extra[1]}\`, which your team marked as printing secrets in secret-guard settings`
  return rules.secretCommands ? SECRET_COMMANDS.find(([re]) => re.test(command))?.[1] : undefined
}

// Borderline commands: often legitimate, so the user is asked instead of the call being refused.
// Each pattern is cut out of the command before the hard checks run, so it can't hide anything else.
const KUBECONFIG_FLAG = new RegExp(`(?:--kubeconfig[=\\s]+|\\bKUBECONFIG=)["']?${HOME}/\\.kube/[^\\s"';|&)]*["']?`, 'g')
const ECR_LOGIN = /\baws\b[^|;&]*\secr\s+get-login-password\b[^|;&]*\|\s*(?:docker|podman|helm(?:\s+registry)?|crane|oras|skopeo)\b[^|;&]*--password-stdin\b/g
const ASSUME_ROLE = /\baws\b[^|;&]*\ssts\s+assume-role\b/g

const ASK_RULES: readonly [RegExp, string][] = [
  [KUBECONFIG_FLAG, 'passes your kubeconfig to a tool; the tool reads it, Claude does not see its contents'],
  [ECR_LOGIN, 'pipes an ECR login password straight into a registry login; the password is not printed'],
  [ASSUME_ROLE, 'prints temporary AWS credentials; secret-guard redacts them from the output'],
]

export type Verdict =
  | { kind: 'allow' }
  | { kind: 'deny'; reason: string; about: 'secrets' | 'heredoc' }
  | { kind: 'ask'; reason: string }

/** Whether a shell command runs, is refused, or needs the user's say-so first. */
export function bashVerdict(command: string, extras: Extras = NO_EXTRAS): Verdict {
  const whole = command.trim()
  if (extras.allow.some(re => re.test(whole))) return { kind: 'allow' }
  const heredoc = extras.rules.heredocs ? heredocReason(command) : undefined
  if (heredoc) return { kind: 'deny', reason: heredoc, about: 'heredoc' }
  const asks: string[] = []
  let rest = command
  for (const [re, why] of ASK_RULES) {
    re.lastIndex = 0
    if (re.test(rest)) {
      asks.push(why)
      rest = rest.replace(re, ' ')
    }
  }
  const reason = bashReason(rest, extras)
  if (reason) return { kind: 'deny', reason, about: 'secrets' }
  return asks.length && extras.rules.askBorderline ? { kind: 'ask', reason: asks.join('; ') } : { kind: 'allow' }
}

// --- Self-protection: always on, and no setting or allowlist entry turns it off. ---

// Claude Code settings files: user, project, local and managed.
const SETTINGS_FILE = /(?:^|\/)(?:\.claude\/settings(?:\.local)?\.json|managed-settings\.json)$/
const SETTINGS_IN_COMMAND = /\bsettings(?:\.local)?\.json\b|\bmanaged-settings\.json\b/
// Words that only appear when a settings change touches this plugin, its options or hooks as a whole.
const GUARD_WORDS = new RegExp(
  ['secret-guard', 'pluginConfigs', 'enabledPlugins', 'disableAllHooks', 'allow_commands', 'extra_paths', 'extra_commands', ...RULE_SETTINGS.map(([, s]) => s)].join('|'),
)
// The installed plugin's own files. The dev folders (plugins-dev, dev-mods) are not under it.
const INSTALLED_PLUGIN = /\.claude\/plugins\/\S*secret-guard/
const PLUGIN_OFF = /\bclaude\s+plugins?\s+(?:disable|uninstall|remove|rm)\b[^|;&]*\bsecret-guard\b/

const SELF_EDIT = "Claude can't change secret-guard's own settings or files, or turn it off. If the user wants a change, they make it themselves in /config or /plugin"

const WRITE_TOOLS = new Set(['Edit', 'MultiEdit', 'Write', 'NotebookEdit'])

/** Why a tool call would weaken secret-guard itself, or undefined when it wouldn't. */
export function selfEditReason(tool: string, input: Readonly<Record<string, unknown>>): string | undefined {
  if (tool === 'Bash') {
    const command = typeof input['command'] === 'string' ? input['command'] : ''
    if (PLUGIN_OFF.test(command)) return `this command disables or removes secret-guard. ${SELF_EDIT}`
    if (INSTALLED_PLUGIN.test(command)) return `this command touches secret-guard's installed files. ${SELF_EDIT}`
    if (SETTINGS_IN_COMMAND.test(command) && GUARD_WORDS.test(command)) return `this command touches secret-guard's settings. ${SELF_EDIT}`
    return undefined
  }
  if (!WRITE_TOOLS.has(tool)) return undefined
  const path = String(input['file_path'] ?? input['notebook_path'] ?? '')
  if (INSTALLED_PLUGIN.test(path)) return `this edits secret-guard's installed files. ${SELF_EDIT}`
  if (SETTINGS_FILE.test(path)) {
    const { file_path: _f, notebook_path: _n, ...change } = input
    if (GUARD_WORDS.test(JSON.stringify(change))) return `this edit touches secret-guard's settings or turns off hooks. ${SELF_EDIT}`
  }
  return undefined
}

// An absolute or ~ path to a secret file, as a file tool receives it.
const SECRET_FILE = new RegExp(
  String.raw`^(?:~|/Users/[^/]+|/home/[^/]+|/root)/` + `(?:\\.(?:${HOME_FILES})$|\\.(?:${HOME_DIRS})(?:/|$)|(?:${HOME_NESTED})$)`,
)

/** True when a file tool's path points at a shell config or credential file. */
export function isSecretPath(path: string, extras: Extras = NO_EXTRAS): boolean {
  const p = path.replace(/\/+$/, '').replace(/\/\.\//g, '/')
  return (extras.rules.credentialFiles && SECRET_FILE.test(p)) || extras.filePaths.some(re => re.test(p))
}
