import type { Register } from 'claude-code'
import { redactValue } from './redact'
import { bashVerdict, isSecretPath } from './rules'

// Input fields that name a file or folder, across the file tools (Read, Grep, Glob, Edit, Write, ...).
const PATH_FIELDS = ['file_path', 'path', 'notebook_path'] as const

// What a refused call tells Claude to pass on. A command typed at the prompt with `!` puts its output
// into the conversation, where this plugin can't redact it, so the advice is a separate terminal.
const ELSEWHERE = "Don't read or print secrets. If the user needs this, they should run it in a separate terminal, not with ! (anything run with ! lands in the conversation unredacted)."

const ALLOW = 'Allow once'
const BLOCK = 'Block'

export const register: Register = on => {
  // Every tool: refuse paths to secret files, then replace secrets in whatever the tool returns.
  on('tool.call', async ($, e, next) => {
    const input = e as unknown as Record<string, unknown>
    const hit = PATH_FIELDS.map(k => input[k]).find(v => typeof v === 'string' && isSecretPath(v))
    if (hit) return { deny: `${$.plugin.name}: ${String(hit)} is a shell config or credential file. ${ELSEWHERE}` }

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

  on('tool.call', { tool: 'Bash' }, async ($, e, next) => {
    const verdict = bashVerdict(e.command)
    if (verdict.kind === 'allow') return next(e)
    if (verdict.kind === 'deny') return { deny: `${$.plugin.name}: blocked, ${verdict.reason}. ${ELSEWHERE}` }

    // Borderline: the user decides. A dismissed dialog, or no one to ask (claude -p), blocks it.
    const shown = e.command.length > 300 ? `${e.command.slice(0, 300)}…` : e.command
    let answer: string
    try {
      answer = await $.ui.ask(`Claude wants to run:\n\n${shown}\n\nThis command ${verdict.reason}. Allow it this once?`, {
        header: 'secret-guard',
        options: [ALLOW, BLOCK],
      })
    } catch {
      answer = BLOCK
    }
    return answer === ALLOW ? next(e) : { deny: `${$.plugin.name}: the user did not allow this command (it ${verdict.reason}). ${ELSEWHERE}` }
  }).catch(($, e, next) => (next.called ? next(e) : { deny: `${$.plugin.name}: its guard failed, so the command was blocked.` }))
}
