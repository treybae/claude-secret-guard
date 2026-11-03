import { expect, test, type TestBody } from 'claude-code/testing'
import { whereOf } from './log'
import { MARK, describeKinds, redactText, redactValue } from './redact'
import { bashReason, bashVerdict, compileExtras, heredocReason, isSecretPath, selfEditReason } from './rules'

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

test('borderline commands ask, and anything else in them still blocks', () => {
  for (const c of [
    'kubectl --kubeconfig ~/.kube/config get pods',
    'kubectl --kubeconfig=$HOME/.kube/prod.yaml -n ns get deploy',
    'KUBECONFIG=~/.kube/staging helm list -A',
    'aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 123.dkr.ecr.us-east-1.amazonaws.com',
    'aws --profile prod ecr get-login-password | helm registry login --username AWS --password-stdin 123.dkr.ecr.us-east-1.amazonaws.com',
    'aws sts assume-role --role-arn arn:aws:iam::1:role/x --role-session-name s',
  ]) {
    expect(bashVerdict(c).kind, c).toBe('ask')
  }
  for (const c of [
    'kubectl --kubeconfig ~/.kube/config get pods; cat ~/.zshrc',
    'KUBECONFIG=~/.kube/config kubectl get secret app -o yaml',
    'aws ecr get-login-password --region us-east-1',
    'aws sts assume-role --role-arn x --role-session-name s && env',
  ]) {
    expect(bashVerdict(c).kind, c).toBe('deny')
  }
  expect(bashVerdict('kubectl get pods').kind).toBe('allow')
})

test('a heredoc that ends early is blocked, the shape of the original incident', () => {
  const incident = [
    "cat > runbook.md <<'EOF'",
    '# Install lnl',
    'Save this script:',
    'cat > ~/bin/lnl <<EOF',
    'aws-vault clear',
    'EOF',
    'chmod +x ~/bin/lnl',
    'EOF',
  ].join('\n')
  expect(heredocReason(incident)).toBeDefined()

  // Even a heredoc that only feeds a command is blocked when its own text holds its marker.
  const yaml = ['kubectl apply -f - <<EOF', 'kind: ConfigMap', 'data:', '  note: |', 'EOF', '    more', 'EOF'].join('\n')
  expect(heredocReason(yaml)).toContain('ends early')
})

test('a heredoc that writes a file is blocked, pointing to the Write tool', () => {
  for (const c of [
    "cat > notes.md <<'EOF'\nhello\nEOF",
    'cat >> log.txt <<EOF\nline\nEOF',
    'cat <<EOF > config.yaml\nkey: value\nEOF',
    'tee out.txt <<EOF\ntext\nEOF',
    'tee -a out.txt <<"END"\ntext\nEND',
    'mkdir -p docs && cat > docs/a.md <<-EOF\n\tindented\n\tEOF',
  ]) {
    expect(heredocReason(c), c).toContain('Write tool')
  }
})

test('heredocs that feed a command and end correctly are allowed', () => {
  for (const c of [
    'kubectl apply -f - <<EOF\napiVersion: v1\nkind: ConfigMap\nEOF',
    "psql <<'SQL'\nselect 1;\nSQL",
    'python3 - <<PY\nprint("hi")\nPY',
    `git commit -m "$(cat <<'EOF'\nfix: a thing\nEOF\n)"`,
    'cat <<EOF\njust printing\nEOF',
    'cat >&2 <<EOF\nwarning\nEOF',
    'cat <<EOF > /dev/null\nnothing\nEOF',
    'cat <<A; cat <<B\none\nA\ntwo\nB',
    'cat <<-EOF\n\tindented\n\tEOF\necho done',
    'grep -c x <<< "herestring"',
    'echo $((1<<3))',
    'cat <<EOF\nunterminated is the shell\'s problem, not an early end',
  ]) {
    expect(heredocReason(c), c).toBeUndefined()
  }
})

test('a blocked heredoc gets its own message, without the secrets advice', async ($, on) => {
  on('tool.call', () => ({ result: {} }))
  const out = await $.tool.call({ tool: 'Bash', command: "cat > notes.md <<'EOF'\nhello\nEOF" })
  const message = String((out as { deny?: string }).deny ?? out.text)
  expect(message).toContain('Write tool')
  expect(message).not.toContain('separate terminal')
  expect(bashVerdict("cat > notes.md <<'EOF'\nhello\nEOF")).toMatchObject({ kind: 'deny', about: 'heredoc' })
})

test('file tool paths to secret files are recognized, others are not', () => {
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

test('Datadog keys, auth headers and AWS credential JSON are redacted', () => {
  const ddApi = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6'
  const ddApp = ddApi + '0a1b2c3d'
  expect(redactText(`DD-API-KEY: ${ddApi}`).text).toBe(`DD-API-KEY: ${MARK}`)
  expect(redactText(`DD-APPLICATION-KEY: ${ddApp}`).text).toBe(`DD-APPLICATION-KEY: ${MARK}`)
  expect(redactText(`DD_APP_KEY=${ddApp}`).text).toBe(`DD_APP_KEY=${MARK}`)
  expect(redactText(`DD_API_KEY=${ddApi}`).text).toBe(`DD_API_KEY=${MARK}`)
  expect(redactText('Authorization: Bearer abcdefghijklmnopqrstuvwx').text).toBe(`Authorization: Bearer ${MARK}`)
  const sts = '{"Credentials": {"AccessKeyId": "' + 'AS' + 'IA' + 'ABCDEFGHIJKLMNOP", "SecretAccessKey": "wJalrXUtnFEMIK7MDENGbPxRfiCYabcdefgh", "SessionToken": "IQoJb3JpZ2luX2VjEXAMPLEabcdef"}}'
  const out = redactText(sts).text
  expect(out).not.toContain('wJalrXUtnFEMI')
  expect(out).not.toContain('IQoJb3JpZ2lu')
  expect(out).not.toContain('ABCDEFGHIJKLMNOP')
})

test('values in Kubernetes Secret manifests are redacted, other documents are not', () => {
  const yaml = [
    'apiVersion: v1',
    'kind: ConfigMap',
    'data:',
    '  LOG_LEVEL: debug',
    '---',
    'apiVersion: v1',
    'kind: Secret',
    'metadata:',
    '  name: app-secrets',
    'type: Opaque',
    'data:',
    '  password: c3VwZXItc2VjcmV0LXZhbHVl',
    '  "api-key": YWJj',
    'stringData:',
    '  config.yaml: |',
    '    user: admin',
    '    pass: hunter2hunter2',
    '  plain: hello',
    '---',
    'kind: Secret',
    'data:',
    '  token: ENC[AES256_GCM,data:abc,type:str]',
    'sops:',
    '  version: 3.8.1',
  ].join('\n')
  const out = redactText(yaml).text
  expect(out).toContain('LOG_LEVEL: debug')
  expect(out).toContain(`  password: ${MARK}`)
  expect(out).toContain(`  "api-key": ${MARK}`)
  expect(out).toContain('  config.yaml: |')
  expect(out).not.toContain('hunter2hunter2')
  expect(out).not.toContain('user: admin')
  expect(out).toContain(`  plain: ${MARK}`)
  expect(out).toContain('name: app-secrets')
  expect(out).toContain('ENC[AES256_GCM')
})

test('ordinary output is left exactly as it was', () => {
  const plain =
    'NAME   READY   STATUS\napp-1  1/1     Running\ncommit 83539a2 Add plugin\nhttps://github.com/treybae/x\n' +
    'kind: Secret\nsecretName: app-secrets\nsecretKey: APP_COOKIE_KEY\nsecretRef:\n  name: app-credentials\nmax_tokens: 4096\nrefresh_token_ttl: 3600'
  expect(redactText(plain)).toEqual({ text: plain, count: 0, kinds: {} })
})

test('redaction reports the kinds it removed, by name and never by value', () => {
  const ddApi = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6'
  const r = redactText(`token ${FAKE.vault}\nDD_API_KEY=${ddApi}\nDD_API_KEY=${ddApi}\nDD-APPLICATION-KEY: ${ddApi}0a1b2c3d\n${FAKE.github}`)
  expect(r.kinds).toEqual({ 'Vault token': 1, 'GitHub token': 1, 'DD_API_KEY value': 2, 'DD-APPLICATION-KEY header': 1 })
  const line = describeKinds(r.kinds)
  expect(line).toBe('DD_API_KEY value ×2, DD-APPLICATION-KEY header, GitHub token, Vault token')
  expect(line).not.toContain(ddApi)
  expect(describeKinds({ a: 1, b: 1, c: 1, d: 1, e: 1, f: 1 })).toBe('a, b, c, d and 2 more')
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
  const message = String((blocked as { deny?: string }).deny ?? blocked.text)
  expect(message).toContain('secret-guard')
  expect(message).toContain('separate terminal, not with !')

  const printed = await $.tool.call({ tool: 'Bash', command: 'vault kv get secret/app' })
  expect(String((printed as { deny?: string }).deny ?? printed.text)).toContain('vault')

  await $.tool.call({ tool: 'Bash', command: 'git status' })
  expect(ran).toEqual(['git status'])
})

// The tests' stand-in for the engine: answers the approval dialog with `pick`, and records commands that ran.
function engine(on: Parameters<TestBody>[1], pick: string | Error, ran: string[]) {
  on('tool.call', (_, e) => {
    const input = e as unknown as { tool: string; command?: string; questions?: { question: string }[] }
    if (input.tool === 'AskUserQuestion') {
      if (pick instanceof Error) throw pick
      const q = input.questions?.[0]?.question ?? ''
      return { result: { questions: input.questions, answers: { [q]: pick } } } as never
    }
    ran.push(String(input.command))
    return { result: {} }
  })
}

const ASK_COMMAND = 'kubectl --kubeconfig ~/.kube/config get pods'

test('a borderline command runs when the user allows it', async ($, on) => {
  const ran: string[] = []
  engine(on, 'Allow once', ran)
  await $.tool.call({ tool: 'Bash', command: ASK_COMMAND })
  expect(ran).toEqual([ASK_COMMAND])
})

test('a borderline command is blocked when the user blocks it or dismisses the dialog', async ($, on) => {
  const ran: string[] = []
  engine(on, 'Block', ran)
  const out = await $.tool.call({ tool: 'Bash', command: ASK_COMMAND })
  expect(String((out as { deny?: string }).deny ?? out.text)).toContain('did not allow')
  expect(ran).toEqual([])
})

test('a borderline command is blocked when no one can answer', async ($, on) => {
  const ran: string[] = []
  engine(on, new Error('dismissed'), ran)
  const out = await $.tool.call({ tool: 'Bash', command: ASK_COMMAND })
  expect(String((out as { deny?: string }).deny ?? out.text)).toContain('secret-guard')
  expect(ran).toEqual([])
})

test('a secret in a tool result is redacted before it comes back', async ($, on) => {
  on('tool.call', () => ({ result: { stdout: `VAULT_TOKEN=${FAKE.vault}\nok`, stderr: '' } }))

  const out = await $.tool.call({ tool: 'Bash', command: 'make debug' })
  const stdout = String((out as { result?: { stdout?: string } }).result?.stdout)
  expect(stdout).not.toContain(FAKE.vault)
  expect(stdout).toContain(MARK)
  expect(stdout).toContain('ok')
})

test('the status line names what was redacted, and the next prompt clears it', async ($, on) => {
  const statuses: (string | undefined)[] = []
  on('ui.status', (_, e) => {
    statuses.push(e.text)
    return { value: undefined }
  })
  on('tool.call', () => ({ result: { stdout: `a ${FAKE.vault}\nb ${FAKE.github}`, stderr: '' } }))
  on('prompt.submit', (_, e) => ({ text: e.text }) as never)

  await $.tool.call({ tool: 'Bash', command: 'make debug' })
  expect(statuses.at(-1)).toBe('redacted 2 secrets · /secret-guard for details')
  expect(String(statuses.at(-1))).not.toContain(FAKE.vault)

  await $.prompt.submit({ text: 'next question' } as never)
  expect(statuses.at(-1)).toBeUndefined()
})

test('/secret-guard shows what was redacted or blocked, where and why, without values', async ($, on) => {
  on('command.register', () => ({ value: { command: 'secret-guard' } }) as never)
  on('session.start', (_, e) => ({ cwd: e.cwd }) as never)
  on('ui.status', () => ({ value: undefined }))
  on('tool.call', (_, e) => {
    const cmd = (e as unknown as { command?: string }).command
    return { result: { stdout: cmd === 'make debug' ? `starting\nVAULT_TOKEN=${FAKE.vault}\ndone` : 'ok', stderr: '' } }
  })
  on('command.run', () => ({ text: 'engine' }) as never)

  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true } as never)
  await $.tool.call({ tool: 'Bash', command: 'make debug' })
  await $.tool.call({ tool: 'Bash', command: 'tail ~/.zshrc' })
  await $.tool.call({ tool: 'Read', file_path: '/Users/me/.vault-token' })

  const report = String((await $.command.run({ command: 'secret-guard', args: '' } as never) as { text?: string }).text)
  expect(report).toContain('3 events this session')
  expect(report).toContain('redacted 1 secret from Bash output')
  expect(report).toContain('where: Bash `make debug`')
  expect(report).toContain('what:  Vault token')
  expect(report).toContain(`lines: VAULT_TOKEN=${MARK}`)
  expect(report).toContain('blocked: Bash `tail ~/.zshrc`')
  expect(report).toContain('why:   this command references a shell config or credential file')
  expect(report).toContain('blocked: Read `/Users/me/.vault-token`')
  expect(report).not.toContain(FAKE.vault)
  expect(report.indexOf('Read `/Users/me/.vault-token`')).toBeLessThan(report.indexOf('make debug'))

  const cleared = String((await $.command.run({ command: 'secret-guard', args: 'clear' } as never) as { text?: string }).text)
  expect(cleared).toBe('Log cleared.')
  const empty = String((await $.command.run({ command: 'secret-guard', args: '' } as never) as { text?: string }).text)
  expect(empty).toBe(
    'Nothing redacted or blocked this session.\n\nAll rules are on.\nSettings: no extra paths, extra commands or allowed commands. Change them under secret-guard in /config.',
  )
})

test('team settings compile extra paths and commands, and report bad entries', () => {
  const extras = compileExtras({
    extra_paths: ['~/.config/mytool', '/etc/myapp/secrets/', 'relative/path', '  '],
    extra_commands: ['\\bmycli\\s+secrets\\s+show\\b', '(unclosed', ''],
  })
  expect(extras.filePaths.length).toBe(2)
  expect(extras.commands.length).toBe(1)
  expect(extras.problems).toEqual([
    'extra_paths entry "relative/path" must start with ~/ or /',
    'extra_commands entry "(unclosed" is not a valid regular expression',
  ])
  // A single string is read one entry per line or comma.
  expect(compileExtras({ extra_paths: '~/.a, ~/.b\n~/.c' }).filePaths.length).toBe(3)
})

test('extra paths block commands and file tools, extra commands block commands', () => {
  const extras = compileExtras({ extra_paths: ['~/.config/mytool', '/etc/myapp/secrets'], extra_commands: ['\\bmycli\\s+secrets\\s+show\\b'] })
  for (const c of ['cat ~/.config/mytool/token', 'ls $HOME/.config/mytool', 'grep x /Users/me/.config/mytool/a', 'cat /etc/myapp/secrets/db', 'mycli secrets show prod']) {
    expect(bashReason(c, extras), c).toBeDefined()
  }
  for (const c of ['cat ~/.config/mytool-notes.md', 'cat /etc/myapp/config', 'mycli secrets list', 'ls ~/.config']) {
    expect(bashReason(c, extras), c).toBeUndefined()
  }
  expect(bashReason('mycli secrets show prod', extras)).toContain('`\\bmycli\\s+secrets\\s+show\\b`')
  for (const p of ['/Users/me/.config/mytool', '/Users/me/.config/mytool/token', '~/.config/mytool/x', '/etc/myapp/secrets/db']) {
    expect(isSecretPath(p, extras), p).toBe(true)
  }
  for (const p of ['/Users/me/.config/mytool2', '/etc/myapp/config', '/Users/me/project/.config/mytool']) {
    expect(isSecretPath(p, extras), p).toBe(false)
  }
  // Without settings, none of these are special.
  expect(bashReason('mycli secrets show prod')).toBeUndefined()
  expect(isSecretPath('/etc/myapp/secrets/db')).toBe(false)
})

test('the plugin reads its settings: an extra command is blocked end to end', { options: { extra_commands: ['\\bmycli\\s+secrets\\s+show\\b'], extra_paths: ['~/.config/mytool'] } }, async ($, on) => {
  const ran: string[] = []
  on('tool.call', (_, e) => {
    ran.push(String((e as unknown as { command?: string; file_path?: string }).command ?? (e as unknown as { file_path?: string }).file_path))
    return { result: {} }
  })
  const out = await $.tool.call({ tool: 'Bash', command: 'mycli secrets show prod' })
  expect(String((out as { deny?: string }).deny ?? out.text)).toContain('secret-guard settings')
  const read = await $.tool.call({ tool: 'Read', file_path: '/Users/me/.config/mytool/token' })
  expect(String((read as { deny?: string }).deny ?? read.text)).toContain('credential file')
  await $.tool.call({ tool: 'Bash', command: 'mycli secrets list' })
  expect(ran).toEqual(['mycli secrets list'])
})

test('each rule can be turned off on its own, and the rest stay on', () => {
  const on = compileExtras({})
  expect(Object.values(on.rules).every(Boolean)).toBe(true)

  const noFiles = compileExtras({ block_credential_files: false })
  expect(bashReason('tail ~/.zshrc', noFiles)).toBeUndefined()
  expect(isSecretPath('/Users/me/.vault-token', noFiles)).toBe(false)
  expect(bashReason('printenv', noFiles)).toBeDefined()

  const noEnv = compileExtras({ block_env_dumps: 'false' })
  expect(bashReason('printenv', noEnv)).toBeUndefined()
  expect(bashReason('vault kv get secret/app', noEnv)).toBeDefined()

  const noCommands = compileExtras({ block_secret_commands: false })
  expect(bashReason('vault kv get secret/app', noCommands)).toBeUndefined()
  expect(bashReason('tail ~/.zshrc', noCommands)).toBeDefined()

  const heredoc = 'cat > notes.txt <<EOF\nhello\nEOF'
  expect(bashVerdict(heredoc).kind).toBe('deny')
  expect(bashVerdict(heredoc, compileExtras({ block_heredocs: false })).kind).toBe('allow')

  // With asking off, a borderline command runs, but anything else in it still blocks.
  const noAsk = compileExtras({ ask_borderline: false })
  expect(bashVerdict('kubectl --kubeconfig ~/.kube/config get pods', noAsk).kind).toBe('allow')
  expect(bashVerdict('kubectl --kubeconfig ~/.kube/config get pods && cat ~/.aws/credentials', noAsk).kind).toBe('deny')

  // Team additions stay on when the built-in rules are off.
  const team = compileExtras({ block_credential_files: false, block_secret_commands: false, extra_paths: ['~/.config/mytool'], extra_commands: ['\\bmycli\\s+secrets\\b'] })
  expect(bashReason('cat ~/.config/mytool/token', team)).toBeDefined()
  expect(bashReason('mycli secrets show', team)).toBeDefined()
})

test('allowed commands skip the blocks only when they match the whole command', () => {
  const extras = compileExtras({ allow_commands: ['vault kv get secret/ci/public-config', 'aws configure get region( --profile \\w+)?', '(bad'] })
  expect(extras.allow.length).toBe(2)
  expect(extras.problems).toEqual(['allow_commands entry "(bad" is not a valid regular expression'])
  expect(bashVerdict('vault kv get secret/ci/public-config', extras).kind).toBe('allow')
  expect(bashVerdict('  aws configure get region --profile dev ', extras).kind).toBe('allow')
  // Anything added around an allowed command is checked as usual.
  expect(bashVerdict('vault kv get secret/ci/public-config; cat ~/.zshrc', extras).kind).toBe('deny')
  expect(bashVerdict('aws configure get aws_secret_access_key', extras).kind).toBe('deny')
})

test('Claude cannot turn off or edit secret-guard through settings, plugin commands or its files', () => {
  const blocked: [string, Record<string, unknown>][] = [
    ['Edit', { file_path: '/Users/me/.claude/settings.json', old_string: '"secret-guard@treybae": true', new_string: '"secret-guard@treybae": false' }],
    ['Edit', { file_path: '/Users/me/work/.claude/settings.local.json', old_string: '{', new_string: '{\n  "disableAllHooks": true,' }],
    ['Edit', { file_path: '/Users/me/.claude/settings.json', old_string: '"redact_output": true', new_string: '"redact_output": false' }],
    ['Write', { file_path: '/Users/me/work/.claude/settings.json', content: '{ "pluginConfigs": {} }' }],
    ['MultiEdit', { file_path: '/Users/me/.claude/settings.json', edits: [{ old_string: 'a', new_string: '"allow_commands": [".*"]' }] }],
    ['Write', { file_path: '/Library/Application Support/ClaudeCode/managed-settings.json', content: '{ "enabledPlugins": {} }' }],
    ['Edit', { file_path: '/Users/me/.claude/plugins/cache/treybae/secret-guard/0.5.0/hooks/rules.ts', old_string: 'a', new_string: 'b' }],
    ['Bash', { command: 'claude plugin disable secret-guard@treybae' }],
    ['Bash', { command: 'claude plugin uninstall secret-guard' }],
    ['Bash', { command: `jq '.enabledPlugins["secret-guard@treybae"] = false' ~/.claude/settings.json > /tmp/s && mv /tmp/s ~/.claude/settings.json` }],
    ['Bash', { command: `sed -i '' 's/"block_heredocs": true/"block_heredocs": false/' .claude/settings.json` }],
    ['Bash', { command: 'rm -rf ~/.claude/plugins/cache/treybae/secret-guard' }],
  ]
  for (const [tool, input] of blocked) expect(selfEditReason(tool, input), `${tool} ${JSON.stringify(input)}`).toBeDefined()

  const allowed: [string, Record<string, unknown>][] = [
    ['Edit', { file_path: '/Users/me/.claude/settings.json', old_string: '"theme": "dark"', new_string: '"theme": "light"' }],
    ['Read', { file_path: '/Users/me/.claude/settings.json' }],
    ['Edit', { file_path: '/Users/me/project/README.md', old_string: 'a', new_string: 'secret-guard pluginConfigs' }],
    ['Edit', { file_path: '/Users/me/.claude/plugins-dev/secret-guard/hooks/rules.ts', old_string: 'a', new_string: 'b' }],
    ['Bash', { command: 'claude plugin install secret-guard --marketplace treybae/claude-secret-guard' }],
    ['Bash', { command: 'jq .theme ~/.claude/settings.json' }],
    ['Bash', { command: 'git commit -m "secret-guard: tidy README"' }],
  ]
  for (const [tool, input] of allowed) expect(selfEditReason(tool, input), `${tool} ${JSON.stringify(input)}`).toBeUndefined()
})

test('self-protection holds end to end, even with every rule off and everything allowed', {
  options: {
    block_credential_files: false, block_env_dumps: false, block_secret_commands: false, block_heredocs: false,
    ask_borderline: false, redact_output: false, allow_commands: ['.*'],
  },
}, async ($, on) => {
  const ran: string[] = []
  on('ui.status', () => ({ value: undefined }))
  on('tool.call', (_, e) => {
    ran.push(String((e as unknown as { command?: string }).command))
    return { result: { stdout: `VAULT_TOKEN=${FAKE.vault}`, stderr: '' } }
  })
  const off = await $.tool.call({ tool: 'Bash', command: 'claude plugin disable secret-guard' })
  expect(String((off as { deny?: string }).deny ?? off.text)).toContain("Claude can't change secret-guard")
  const out = await $.tool.call({ tool: 'Bash', command: 'printenv' })
  // With redaction off, the output comes back as the tool gave it.
  expect(String((out as { result?: { stdout?: string } }).result?.stdout)).toContain(FAKE.vault)
  expect(ran).toEqual(['printenv'])
})

test('/secret-guard names the rules that are off', { options: { redact_output: false, block_heredocs: false, allow_commands: ['make deploy'] } }, async ($, on) => {
  on('command.run', () => ({ text: 'engine' }) as never)
  const report = String((await $.command.run({ command: 'secret-guard', args: '' } as never) as { text?: string }).text)
  expect(report).toContain('Rules turned off: heredoc blocks (block_heredocs), output redaction (redact_output).')
  expect(report).toContain('0 extra paths, 0 extra commands and 1 allowed command')
})

test('a command line that itself holds a secret is redacted in the log', () => {
  expect(whereOf('Bash', { command: `curl -H "Authorization: Bearer abcdefghijklmnopqrstuvwx" https://api.example.com` })).toBe(
    `Bash \`curl -H "Authorization: Bearer ${MARK}" https://api.example.com\``,
  )
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
