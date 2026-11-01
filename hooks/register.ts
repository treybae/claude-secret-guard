import type { Register } from 'claude-code'
import { redactValue } from './redact'
import { bashReason, isSecretPath } from './rules'

// Input fields that name a file or folder, across the file tools (Read, Grep, Glob, Edit, Write, ...).
const PATH_FIELDS = ['file_path', 'path', 'notebook_path'] as const

export const register: Register = on => {
  // Every tool: refuse paths to secret files, then replace secrets in whatever the tool returns.
  on('tool.call', async ($, e, next) => {
    const input = e as unknown as Record<string, unknown>
    const hit = PATH_FIELDS.map(k => input[k]).find(v => typeof v === 'string' && isSecretPath(v))
    if (hit) return { deny: `${$.plugin.name}: ${String(hit)} is a shell config or credential file. Don't read secrets; ask the user instead.` }

    const out = await next(e)
    if (out.deny !== undefined) return out
    const { value, count } = redactValue(out.result)
    if (count === 0) return out
    $.ui.status(`secret-guard redacted ${count} secret${count === 1 ? '' : 's'} from ${e.tool} output`)
    return { result: value as typeof out.result, context: out.context }
  }).catch(($, e, next) =>
    next.called
      ? { deny: `${$.plugin.name}: output redaction failed, so the result was withheld.` }
      : { deny: `${$.plugin.name}: its guard failed, so the tool call was blocked.` },
  )

  on('tool.call', { tool: 'Bash' }, ($, e, next) => {
    const reason = bashReason(e.command)
    return reason ? { deny: `${$.plugin.name}: blocked, ${reason}. Don't read or print secrets; ask the user instead, or they can run it themselves with !.` } : next(e)
  }).catch(($, e, next) => (next.called ? next(e) : { deny: `${$.plugin.name}: its guard failed, so the command was blocked.` }))
}
