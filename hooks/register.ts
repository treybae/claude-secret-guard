import type { Register } from 'claude-code'
import { bashReason, isSecretPath } from './rules'

// Input fields that name a file or folder, across the file tools (Read, Grep, Glob, Edit, Write, ...).
const PATH_FIELDS = ['file_path', 'path', 'notebook_path'] as const

export const register: Register = on => {
  on('tool.call', { tool: 'Bash' }, ($, e, next) => {
    const reason = bashReason(e.command)
    return reason ? { deny: `${$.plugin.name}: blocked, ${reason}. Don't read or print secrets; ask the user instead.` } : next(e)
  }).catch(($, e, next) => (next.called ? next(e) : { deny: `${$.plugin.name}: its guard failed, so the command was blocked.` }))

  on('tool.call', ($, e, next) => {
    const input = e as unknown as Record<string, unknown>
    const hit = PATH_FIELDS.map(k => input[k]).find(v => typeof v === 'string' && isSecretPath(v))
    return hit ? { deny: `${$.plugin.name}: ${String(hit)} is a shell config or credential file. Don't read secrets; ask the user instead.` } : next(e)
  }).catch(($, e, next) => (next.called ? next(e) : { deny: `${$.plugin.name}: its guard failed, so the tool call was blocked.` }))
}
