// Replaces anything shaped like a key or token in tool output before the model reads it.

export const MARK = '[REDACTED by secret-guard]'

/** How many secrets of each kind were redacted, by a label safe to show (never the value). */
export type Kinds = Record<string, number>

// Whole-match patterns: the match itself is the secret.
const WHOLE: readonly [RegExp, string][] = [
  [/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g, 'private key'],
  [/\bhv[sbr]\.[A-Za-z0-9_-]{20,}/g, 'Vault token'],
  [/\bgh[pousr]_[A-Za-z0-9]{36,}\b/g, 'GitHub token'],
  [/\bgithub_pat_[A-Za-z0-9_]{22,}\b/g, 'GitHub token'],
  [/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, 'AWS access key ID'],
  [/\bxox[abeoprs]-[A-Za-z0-9-]{10,}/g, 'Slack token'],
  [/\bops_eyJ[A-Za-z0-9_-]{20,}/g, '1Password service account token'],
  [/\bsk-ant-[A-Za-z0-9_-]{20,}/g, 'Anthropic API key'],
  [/\bsk_live_[A-Za-z0-9]{20,}\b/g, 'Stripe live key'],
  [/\bAIza[0-9A-Za-z_-]{35}\b/g, 'Google API key'],
  [/\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, 'JWT'],
]

// Assignments: keep the name, replace the value. Values that look like placeholders
// (`$VAR`, `${VAR}`, `<value>`, `op://...`, `***`, SOPS `ENC[...]`) are left alone.
const ASSIGNMENT =
  /\b((?:aws_secret_access_key|aws_session_token|secretaccesskey|[A-Za-z0-9_]*(?:password|passwd|secret|token|api_key|apikey|app_key|appkey|application_key|private_key))["']?\s*[:=]\s*["']?)(?!\$|<|op:\/\/|\*{3}|\[REDACTED|ENC\[)([^\s"'`,;]{12,})/gi

// HTTP headers that carry keys, such as Datadog's `DD-API-KEY: <32 hex>` and `DD-APPLICATION-KEY: <40 hex>`.
const KEY_HEADER = /\b((?:dd-api-key|dd-application-key|x-api-key|x-auth-token|authorization)\s*:\s*(?:Bearer\s+|Basic\s+|token\s+)?)(?!\$|<|\[REDACTED)([A-Za-z0-9._~+/=-]{16,})/gi

function add(kinds: Kinds, label: string, n = 1): void {
  kinds[label] = (kinds[label] ?? 0) + n
}

// The name an assignment or header shows the model, e.g. `DD_API_KEY value` or `DD-API-KEY header`.
function nameOf(prefix: string): string {
  return prefix.replace(/["'\s]*[:=].*$/s, '').replace(/^["']/, '')
}

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

/** The text with secrets replaced, how many were, and of which kinds. */
export function redactText(text: string): { text: string; count: number; kinds: Kinds } {
  const kinds: Kinds = {}
  let out = text
  for (const [re, label] of WHOLE) {
    out = out.replace(re, () => {
      add(kinds, label)
      return MARK
    })
  }
  out = out.replace(ASSIGNMENT, (_m, prefix: string) => {
    add(kinds, `${nameOf(prefix)} value`)
    return `${prefix}${MARK}`
  })
  out = out.replace(KEY_HEADER, (_m, prefix: string) => {
    add(kinds, `${nameOf(prefix)} header`)
    return `${prefix}${MARK}`
  })
  const manifests = redactSecretManifests(out)
  if (manifests.count) add(kinds, 'Kubernetes Secret value', manifests.count)
  const count = Object.values(kinds).reduce((a, b) => a + b, 0)
  return { text: manifests.text, count, kinds }
}

/** A copy of any JSON-like value with every string redacted, the total count, and the kinds. */
export function redactValue(value: unknown): { value: unknown; count: number; kinds: Kinds } {
  if (typeof value === 'string') {
    const r = redactText(value)
    return { value: r.text, count: r.count, kinds: r.kinds }
  }
  const kinds: Kinds = {}
  let count = 0
  const merge = (r: { value: unknown; count: number; kinds: Kinds }) => {
    count += r.count
    for (const [k, n] of Object.entries(r.kinds)) add(kinds, k, n)
    return r.value
  }
  if (Array.isArray(value)) return { value: value.map(v => merge(redactValue(v))), count, kinds }
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(value)) out[k] = merge(redactValue(v))
    return { value: out, count, kinds }
  }
  return { value, count: 0, kinds }
}

/** A short status line naming what was redacted, e.g. "Vault token, DD_API_KEY value ×2". */
export function describeKinds(kinds: Kinds, max = 4): string {
  const parts = Object.entries(kinds)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([k, n]) => (n > 1 ? `${k} ×${n}` : k))
  return parts.length > max ? `${parts.slice(0, max).join(', ')} and ${parts.length - max} more` : parts.join(', ')
}
