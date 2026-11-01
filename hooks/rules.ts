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
    /\baws\b[^|;&]*\s(?:configure\s+(?:get|export-credentials)|sts\s+(?:get-session-token|assume-role)|ecr\s+get-login-password|secretsmanager\s+get-secret-value|ssm\s+get-parameters?\b[^|;&]*--with-decryption)\b/,
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

/** Why a shell command must not run, or undefined when it may. */
export function bashReason(command: string): string | undefined {
  if (HOME_PATH.test(command) || BARE_NAME.test(command)) {
    return 'this command references a shell config or credential file (~/.zshrc, ~/.aws, ~/.ssh, ~/.vault-token, ...)'
  }
  if (ENV_DUMP.test(command)) return 'this command prints environment variables, which may hold secrets'
  return SECRET_COMMANDS.find(([re]) => re.test(command))?.[1]
}

// An absolute or ~ path to a secret file, as a file tool receives it.
const SECRET_FILE = new RegExp(
  String.raw`^(?:~|/Users/[^/]+|/home/[^/]+|/root)/` + `(?:\\.(?:${HOME_FILES})$|\\.(?:${HOME_DIRS})(?:/|$)|(?:${HOME_NESTED})$)`,
)

/** True when a file tool's path points at a shell config or credential file. */
export function isSecretPath(path: string): boolean {
  return SECRET_FILE.test(path.replace(/\/+$/, '').replace(/\/\.\//g, '/'))
}
