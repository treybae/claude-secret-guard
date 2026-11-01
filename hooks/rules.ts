// Pure checks shared by the hooks and the tests.

const SHELL_FILES = 'zshrc|zprofile|zshenv|zlogin|bashrc|bash_profile|profile|netrc'
const SECRET_DIRS = 'aws|ssh|kube'

const HOME = String.raw`(?:~|\$HOME|\$\{HOME\}|/Users/[^/\s]+|/home/[^/\s]+)`
const END = String.raw`(?=[\s"';|&)]|$)`

// A home-rooted secret path in a shell command: ~/.zshrc, $HOME/.aws/..., /Users/me/.kube/config.
const HOME_PATH = new RegExp(
  `${HOME}/(?:\\.(?:${SHELL_FILES})${END}|\\.(?:aws|ssh|config/op)(?=/|[\\s"';|&)]|$)|\\.docker/config\\.json|\\.kube/config)`,
)

// The same files spelled relative to ~, after `cd ~`: cat .zshrc, ls .aws/.
const BARE_NAME = new RegExp(
  `(?:^|[\\s/"'=])\\.(?:${SHELL_FILES})${END}|(?:^|[\\s"'=])\\.(?:${SECRET_DIRS})(?=/|[\\s"';|&)]|$)`,
)

// Bare env/printenv (or printenv NAME), export -p, declare -x, and a bare `set` print the environment.
// `env FOO=bar cmd` and `set -euo pipefail` stay allowed.
const ENV_DUMP = new RegExp(
  String.raw`(?:^|[;&|(` + '`' + String.raw`]|\$\()\s*(?:env|printenv)(?:\s*(?:$|[;&|)` + '`' + String.raw`>])|\s+[A-Za-z_]*(?:$|[;&|)` + '`' + String.raw`>]))` +
    String.raw`|(?:^|[;&|(]|\$\()\s*(?:export\s+-p|declare\s+-x|set)\s*(?:$|[;&|)>])`,
)

/** Why a shell command must not run, or undefined when it may. */
export function bashReason(command: string): string | undefined {
  if (HOME_PATH.test(command) || BARE_NAME.test(command)) {
    return 'this command references a shell config or credential file (~/.zshrc, ~/.aws, ~/.ssh, ~/.kube/config, ...)'
  }
  if (ENV_DUMP.test(command)) return 'this command prints environment variables, which may hold secrets'
  return undefined
}

// An absolute or ~ path to a secret file, as a file tool receives it.
const SECRET_FILE = new RegExp(
  String.raw`^(?:~|/Users/[^/]+|/home/[^/]+|/root)/` +
    `(?:\\.(?:${SHELL_FILES})$|\\.(?:aws|ssh|config/op)(?:/|$)|\\.docker/config\\.json$|\\.kube/config$)`,
)

/** True when a file tool's path points at a shell config or credential file. */
export function isSecretPath(path: string): boolean {
  return SECRET_FILE.test(path.replace(/\/+$/, '').replace(/\/\.\//g, '/'))
}
