import { expect, test } from 'claude-code/testing'
import { MARK, redactText, redactValue } from './redact'
import { bashReason, isSecretPath } from './rules'

const BLOCKED_COMMANDS = [
  // shell config and credential files
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
  'ls ~/.kube/cache',
  'cat ~/.docker/config.json',
  'ls ~/.config/op',
  'cat ~/.vault-token',
  'cd ~ && cat .vault-token',
  'cat ~/.config/gh/hosts.yml',
  'cat ~/.git-credentials',
  'cat ~/.npmrc',
  'cat ~/.pypirc',
  'cat ~/.terraformrc',
  'cat ~/.terraform.d/credentials.tfrc.json',
  'ls ~/.config/gcloud',
  'ls ~/.azure',
  'ls ~/.gnupg',
  // environment dumps
  'env',
  'printenv',
  'printenv API_TOKEN',
  'env | grep TOKEN',
  'export -p',
  'declare -x',
  'set',
  'echo hi; set',
  // commands that print secrets
  'op read "op://Private/item/credential"',
  'op item get abc --reveal',
  'op run --no-masking -- env',
  'vault read secret/data/app',
  'vault kv get -field=password secret/app',
  'vault token lookup',
  'vault token create -policy=x',
  'vault print token',
  'vault login -method=oidc',
  'aws configure get aws_secret_access_key',
  'aws --profile prod configure export-credentials',
  'aws sts get-session-token',
  'aws sts assume-role --role-arn arn:aws:iam::1:role/x --role-session-name s',
  'aws ecr get-login-password --region us-east-1',
  'aws secretsmanager get-secret-value --secret-id app',
  'aws ssm get-parameter --name /app/key --with-decryption',
  'gh auth token',
  'gh auth status --show-token',
  'kubectl get secret app -o yaml',
  'kubectl --context x -n ns get secret app -ojson',
  'kubectl get secrets --output=jsonpath={.items}',
  'kubectl get secret/app -o go-template={{.data}}',
  'security find-generic-password -s svc -w',
  'gcloud auth print-access-token',
  'az account get-access-token',
  'echo url=https://github.com | git credential fill',
]

const ALLOWED_COMMANDS = [
  'ls',
  'git status',
  'git log --oneline -3',
  'set -euo pipefail; make test',
  'set -e; go test ./...',
  'env FOO=bar go test ./...',
  'kubectl get pods',
  'kubectl get pods -o yaml',
  'kubectl get secrets',
  'kubectl describe secret app',
  'kubectl --context x get pods',
  'cat README.md',
  'cat docs/README.md',
  'cat .gitignore',
  'cat .npmrc',
  'ls .claude/',
  'grep -rn zshrc docs/',
  'echo $SETTINGS',
  'go env GOPATH',
  'pnpm test',
  'vault status',
  'vault kv list secret/',
  'aws s3 ls',
  'aws sts get-caller-identity',
  'gh pr list',
  'gh auth status',
  'op item list',
  'op run -- make deploy',
  'security find-generic-password -s svc',
]

test('shell commands that read secrets, dump the environment or print secrets are blocked', () => {
  for (const c of BLOCKED_COMMANDS) expect(bashReason(c), c).toBeDefined()
})

test('everyday shell commands are allowed', () => {
  for (const c of ALLOWED_COMMANDS) expect(bashReason(c), c).toBeUndefined()
})

test('file tool paths to secret files are recognised, others are not', () => {
  for (const p of [
    '/Users/me/.zshrc', '/home/me/.bash_profile', '~/.netrc', '/Users/me/.aws/credentials', '/Users/me/.ssh', '/Users/me/.ssh/',
    '/Users/me/.kube/config', '/Users/me/.kube/cache/x', '/Users/me/.config/op/config', '/Users/me/./.zshrc', '/Users/me/.vault-token',
    '/Users/me/.config/gh/hosts.yml', '/Users/me/.git-credentials', '/Users/me/.npmrc', '/Users/me/.terraform.d/credentials.tfrc.json',
    '/Users/me/.gnupg/private-keys-v1.d', '/Users/me/.config/gcloud/credentials.db', '/Users/me/.azure/msal_token_cache.json',
  ]) {
    expect(isSecretPath(p), p).toBe(true)
  }
  for (const p of [
    '/Users/me/Development/ops/.gitignore', '/Users/me/Development/ops/README.md', '/Users/me/.claude/settings.json',
    '/Users/me/project/.aws-notes.md', '/Users/me/project/docs/zshrc.md', '/Users/me/project/.npmrc', '/Users/me/.config/git/config',
  ]) {
    expect(isSecretPath(p), p).toBe(false)
  }
})

// Fake tokens built at run time, so the files themselves hold nothing a secret scanner flags.
const FAKE = {
  vault: 'hv' + 's.' + 'A1b2C3d4E5f6G7h8I9j0K1l2',
  github: 'gh' + 'p_' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8',
  githubPat: 'github' + '_pat_' + '11ABCDEFG0abcdefghijkl_mnopqrstuvwxyz0123',
  aws: 'AK' + 'IA' + 'ABCDEFGHIJKLMNOP',
  slack: 'xo' + 'xb-' + '123456789012-abcdefghij',
  jwt: 'ey' + 'JhbGciOiJIUzI1NiJ9.' + 'ey' + 'JzdWIiOiIxMjM0NTY3ODkwIn0.' + 'abcdefghijklmnopqrst',
  anthropic: 'sk' + '-ant-' + 'api03-abcdefghijklmnopqrstuvwx',
  key: '-----BEGIN ' + 'OPENSSH PRIVATE KEY-----\nAAAA\nBBBB\n-----END ' + 'OPENSSH PRIVATE KEY-----',
}

test('each known token shape is redacted', () => {
  for (const [name, secret] of Object.entries(FAKE)) {
    const r = redactText(`before ${secret} after`)
    expect(r.text, name).toBe(`before ${MARK} after`)
    expect(r.count, name).toBe(1)
  }
})

test('assignments keep their name and lose their value, placeholders are left alone', () => {
  expect(redactText('SERVICE_API_TOKEN=abcdefghijklmnop1234').text).toBe(`SERVICE_API_TOKEN=${MARK}`)
  expect(redactText('aws_secret_access_key = wJalrXUtnFEMIabcdefghijk').text).toBe(`aws_secret_access_key = ${MARK}`)
  expect(redactText('"password": "correct-horse-battery"').text).toBe(`"password": "${MARK}"`)
  for (const kept of ['TOKEN=$TOKEN_FROM_ENV', 'API_KEY=${API_KEY}', 'password: <your-password-here>', 'TOKEN="op://Private/item/credential"', 'token: ***', 'secret=short']) {
    expect(redactText(kept).text, kept).toBe(kept)
  }
})

test('ordinary output is left exactly as it was', () => {
  const plain =
    'NAME   READY   STATUS\napp-1  1/1     Running\ncommit 83539a2 Add plugin\nhttps://github.com/treybae/x\n' +
    'kind: Secret\nsecretName: app-secrets\nsecretKey: APP_COOKIE_KEY\nsecretRef:\n  name: app-credentials\nmax_tokens: 4096\nrefresh_token_ttl: 3600'
  expect(redactText(plain)).toEqual({ text: plain, count: 0 })
})

test('redaction walks nested results', () => {
  const r = redactValue({ stdout: `token ${FAKE.vault}`, files: [{ content: FAKE.github }], exit: 0 })
  expect(r.count).toBe(2)
  expect(r.value).toEqual({ stdout: `token ${MARK}`, files: [{ content: MARK }], exit: 0 })
})

test('a blocked Bash call never reaches the tool, an allowed one does', async ($, on) => {
  const ran: string[] = []
  on('tool.call', (_, e) => {
    ran.push(String((e as unknown as { command?: string }).command))
    return { result: {} }
  })

  const blocked = await $.tool.call({ tool: 'Bash', command: 'tail ~/.zshrc' })
  expect(String((blocked as { deny?: string }).deny ?? blocked.text)).toContain('secret-guard')

  const printed = await $.tool.call({ tool: 'Bash', command: 'vault kv get secret/app' })
  expect(String((printed as { deny?: string }).deny ?? printed.text)).toContain('vault')

  await $.tool.call({ tool: 'Bash', command: 'git status' })
  expect(ran).toEqual(['git status'])
})

test('a secret in a tool result is redacted before it comes back', async ($, on) => {
  on('tool.call', () => ({ result: { stdout: `VAULT_TOKEN=${FAKE.vault}\nok`, stderr: '' } }))

  const out = await $.tool.call({ tool: 'Bash', command: 'make debug' })
  const stdout = String((out as { result?: { stdout?: string } }).result?.stdout)
  expect(stdout).not.toContain(FAKE.vault)
  expect(stdout).toContain(MARK)
  expect(stdout).toContain('ok')
})

test('a result with no secrets passes through unchanged', async ($, on) => {
  on('tool.call', () => ({ result: { stdout: 'all good', stderr: '' } }))

  const out = await $.tool.call({ tool: 'Bash', command: 'make test' })
  expect((out as { result?: { stdout?: string } }).result?.stdout).toBe('all good')
})

test('a Read of a secret file is blocked, a normal file passes', async ($, on) => {
  const ran: string[] = []
  on('tool.call', (_, e) => {
    ran.push(String((e as unknown as { file_path?: string }).file_path))
    return { result: {} }
  })

  const blocked = await $.tool.call({ tool: 'Read', file_path: '/Users/me/.vault-token' })
  expect(String((blocked as { deny?: string }).deny ?? blocked.text)).toContain('credential file')

  await $.tool.call({ tool: 'Read', file_path: '/Users/me/project/README.md' })
  expect(ran).toEqual(['/Users/me/project/README.md'])
})
