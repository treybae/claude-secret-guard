import { expect, test } from 'claude-code/testing'
import { bashReason, isSecretPath } from './rules'

const BLOCKED_COMMANDS = [
  'tail ~/.zshrc',
  'cat $HOME/.zprofile',
  'cat ${HOME}/.bashrc',
  'grep KEY /Users/someone/.zshrc',
  'cd ~ && cat .zshrc',
  'cd ~; ls .aws/',
  'cat ~/.aws/credentials',
  'ls ~/.ssh',
  'cat .ssh/id_rsa',
  'head ~/.kube/config',
  'cat ~/.docker/config.json',
  'ls ~/.config/op',
  'env',
  'printenv',
  'printenv API_TOKEN',
  'env | grep TOKEN',
  'export -p',
  'declare -x',
  'set',
  'echo hi; set',
]

const ALLOWED_COMMANDS = [
  'ls',
  'git status',
  'git log --oneline -3',
  'set -euo pipefail; make test',
  'set -e; go test ./...',
  'env FOO=bar go test ./...',
  'kubectl get pods',
  'kubectl --context x get pods',
  'cat README.md',
  'cat docs/README.md',
  'cat .gitignore',
  'ls .claude/',
  'grep -rn zshrc docs/',
  'echo $SETTINGS',
  'go env GOPATH',
  'pnpm test',
]

test('shell commands that read secrets or dump the environment are blocked', () => {
  for (const c of BLOCKED_COMMANDS) expect(bashReason(c), c).toBeDefined()
})

test('everyday shell commands are allowed', () => {
  for (const c of ALLOWED_COMMANDS) expect(bashReason(c), c).toBeUndefined()
})

test('file tool paths to secret files are recognised, others are not', () => {
  for (const p of ['/Users/me/.zshrc', '/home/me/.bash_profile', '~/.netrc', '/Users/me/.aws/credentials', '/Users/me/.ssh', '/Users/me/.ssh/', '/Users/me/.kube/config', '/Users/me/.config/op/config', '/Users/me/./.zshrc']) {
    expect(isSecretPath(p), p).toBe(true)
  }
  for (const p of ['/Users/me/Development/ops/.gitignore', '/Users/me/Development/ops/README.md', '/Users/me/.claude/settings.json', '/Users/me/project/.aws-notes.md', '/Users/me/project/docs/zshrc.md']) {
    expect(isSecretPath(p), p).toBe(false)
  }
})

test('a blocked Bash call never reaches the tool, an allowed one does', async ($, on) => {
  const ran: string[] = []
  on('tool.call', (_, e) => {
    ran.push(String((e as unknown as { command?: string; file_path?: string }).command ?? (e as unknown as { file_path?: string }).file_path))
    return { result: {} }
  })

  const blocked = await $.tool.call({ tool: 'Bash', command: 'tail ~/.zshrc' })
  expect(String((blocked as { deny?: string }).deny ?? blocked.text)).toContain('secret-guard')

  await $.tool.call({ tool: 'Bash', command: 'git status' })
  expect(ran).toEqual(['git status'])
})

test('a Read of a secret file is blocked, a normal file passes', async ($, on) => {
  const ran: string[] = []
  on('tool.call', (_, e) => {
    ran.push(String((e as unknown as { file_path?: string }).file_path))
    return { result: {} }
  })

  const blocked = await $.tool.call({ tool: 'Read', file_path: '/Users/me/.zshrc' })
  expect(String((blocked as { deny?: string }).deny ?? blocked.text)).toContain('credential file')

  await $.tool.call({ tool: 'Read', file_path: '/Users/me/project/README.md' })
  expect(ran).toEqual(['/Users/me/project/README.md'])
})
