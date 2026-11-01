// Replaces anything shaped like a key or token in tool output before the model reads it.

export const MARK = '[REDACTED by secret-guard]'

// Whole-match patterns: the match itself is the secret.
const WHOLE: readonly RegExp[] = [
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
  /\bhv[sbr]\.[A-Za-z0-9_-]{20,}/g, // Vault service, batch and recovery tokens
  /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g, // GitHub tokens
  /\bgithub_pat_[A-Za-z0-9_]{22,}\b/g,
  /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, // AWS access key ids
  /\bxox[abeoprs]-[A-Za-z0-9-]{10,}/g, // Slack tokens
  /\bops_eyJ[A-Za-z0-9_-]{20,}/g, // 1Password service account tokens
  /\bsk-ant-[A-Za-z0-9_-]{20,}/g, // Anthropic API keys
  /\bsk_live_[A-Za-z0-9]{20,}\b/g, // Stripe live keys
  /\bAIza[0-9A-Za-z_-]{35}\b/g, // Google API keys
  /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, // JWTs
]

// Assignments: keep the name, replace the value. Values that look like placeholders
// (`$VAR`, `${VAR}`, `<value>`, `op://...`, `***`) are left alone.
const ASSIGNMENT =
  /\b((?:aws_secret_access_key|aws_session_token|secretaccesskey|[A-Za-z0-9_]*(?:password|passwd|secret|token|api_key|apikey|app_key|appkey|application_key|private_key))["']?\s*[:=]\s*["']?)(?!\$|<|op:\/\/|\*{3}|\[REDACTED|ENC\[)([^\s"'`,;]{12,})/gi

// HTTP headers that carry keys, such as Datadog's `DD-API-KEY: <32 hex>` and `DD-APPLICATION-KEY: <40 hex>`.
const KEY_HEADER = /\b((?:dd-api-key|dd-application-key|x-api-key|x-auth-token|authorization)\s*:\s*(?:Bearer\s+|Basic\s+|token\s+)?)(?!\$|<|\[REDACTED)([A-Za-z0-9._~+/=-]{16,})/gi

// The values under `data:` and `stringData:` in a Kubernetes Secret manifest (YAML), one document at a time.
// SOPS-encrypted documents are left alone: their values are already ciphertext.
function redactSecretManifests(text: string): { text: string; count: number } {
  if (!/^\s*kind:\s*["']?Secret["']?\s*$/m.test(text)) return { text, count: 0 }
  let count = 0
  const docs = text.split(/^(?=---\s*$)/m).map(doc => {
    if (!/^\s*kind:\s*["']?Secret["']?\s*$/m.test(doc) || /^\s*sops:\s*$/m.test(doc) || doc.includes('ENC[')) return doc
    let blockIndent = -1
    let literalIndent = -1 // inside a `key: |` or `key: >` value, the key's indent
    return doc
      .split('\n')
      .map(line => {
        const header = /^(\s*)(?:data|stringData):\s*$/.exec(line)
        if (header) {
          blockIndent = header[1]!.length
          literalIndent = -1
          return line
        }
        if (blockIndent < 0 || line.trim() === '') return line
        const indent = /^\s*/.exec(line)![0].length
        if (indent <= blockIndent) {
          blockIndent = -1
          literalIndent = -1
          return line
        }
        if (literalIndent >= 0 && indent > literalIndent) {
          count++
          return `${' '.repeat(indent)}${MARK}`
        }
        literalIndent = -1
        const literal = /^(\s+)["']?[^:#\s][^:]*["']?:\s*[|>][-+]?\s*$/.exec(line)
        if (literal) {
          literalIndent = literal[1]!.length
          return line
        }
        const entry = /^(\s+["']?[^:#\s][^:]*["']?:\s*)(\S.*)$/.exec(line)
        if (!entry || entry[2]!.startsWith('[REDACTED')) return line
        count++
        return `${entry[1]}${MARK}`
      })
      .join('\n')
  })
  return { text: docs.join(''), count }
}

/** The text with secrets replaced, and how many were. */
export function redactText(text: string): { text: string; count: number } {
  let count = 0
  let out = text
  for (const re of WHOLE) {
    out = out.replace(re, () => {
      count++
      return MARK
    })
  }
  for (const re of [ASSIGNMENT, KEY_HEADER]) {
    out = out.replace(re, (_m, name: string) => {
      count++
      return `${name}${MARK}`
    })
  }
  const manifests = redactSecretManifests(out)
  return { text: manifests.text, count: count + manifests.count }
}

/** A copy of any JSON-like value with every string redacted, and the total count. */
export function redactValue(value: unknown): { value: unknown; count: number } {
  if (typeof value === 'string') {
    const r = redactText(value)
    return { value: r.text, count: r.count }
  }
  if (Array.isArray(value)) {
    let count = 0
    const out = value.map(v => {
      const r = redactValue(v)
      count += r.count
      return r.value
    })
    return { value: out, count }
  }
  if (value !== null && typeof value === 'object') {
    let count = 0
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(value)) {
      const r = redactValue(v)
      count += r.count
      out[k] = r.value
    }
    return { value: out, count }
  }
  return { value, count: 0 }
}
