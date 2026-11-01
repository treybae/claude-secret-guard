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

/** Why a shell command must not run, or undefined when it may. */
export function bashReason(command: string): string | undefined {
  if (HOME_PATH.test(command) || BARE_NAME.test(command)) {
    return 'this command references a shell config or credential file (~/.zshrc, ~/.aws, ~/.ssh, ~/.vault-token, ...)'
  }
  if (ENV_DUMP.test(command)) return 'this command prints environment variables, which may hold secrets'
  return SECRET_COMMANDS.find(([re]) => re.test(command))?.[1]
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
export function bashVerdict(command: string): Verdict {
  const heredoc = heredocReason(command)
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
  const reason = bashReason(rest)
  if (reason) return { kind: 'deny', reason, about: 'secrets' }
  return asks.length ? { kind: 'ask', reason: asks.join('; ') } : { kind: 'allow' }
}

// An absolute or ~ path to a secret file, as a file tool receives it.
const SECRET_FILE = new RegExp(
  String.raw`^(?:~|/Users/[^/]+|/home/[^/]+|/root)/` + `(?:\\.(?:${HOME_FILES})$|\\.(?:${HOME_DIRS})(?:/|$)|(?:${HOME_NESTED})$)`,
)

/** True when a file tool's path points at a shell config or credential file. */
export function isSecretPath(path: string): boolean {
  return SECRET_FILE.test(path.replace(/\/+$/, '').replace(/\/\.\//g, '/'))
}
