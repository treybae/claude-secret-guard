import type { Hook, Register } from 'claude-code'
import { createLog, formatLog, redactedLines, whereOf, type Event } from './log'
import { describeKinds, redactValue } from './redact'
import { bashVerdict, isSecretPath } from './rules'

// Input fields that name a file or folder, across the file tools (Read, Grep, Glob, Edit, Write, ...).
const PATH_FIELDS = ['file_path', 'path', 'notebook_path'] as const

// What a refused call tells Claude to pass on. A command typed at the prompt with `!` puts its output
// into the conversation, where this plugin can't redact it, so the advice is a separate terminal.
const ELSEWHERE = "Don't read or print secrets. If the user needs this, they should run it in a separate terminal, not with ! (anything run with ! lands in the conversation unredacted)."

const ALLOW = 'Allow once'
const BLOCK = 'Block'
const COMMAND = 'secret-guard'

type Engine = Parameters<Hook<'tool.call'>>[0]
// A log event before its timestamp is added, kept as a union so each action keeps its own fields.
type Unstamped = Event extends infer E ? (E extends unknown ? Omit<E, 'at'> : never) : never

// This session's redactions and blocks, for /secret-guard. Only redacted text goes in.
// Module state: a reload of the plugin starts it empty.
const log = createLog()

// Logging is best-effort: a failure here must never change whether a call is blocked or redacted.
async function record($: Engine, event: Unstamped): Promise<void> {
  try {
    let at: number
    try {
      at = await $.clock.now()
    } catch {
      at = Date.now()
    }
    log.add({ ...event, at } as Event)
  } catch {
    // nothing to do: the guard's decision stands without its log line
  }
}

export const register: Register = on => {
  log.clear()

  on('session.start', async ($, e, next) => {
    await $.command.register({ name: COMMAND, description: 'Show what secret-guard redacted or blocked this session, and why', argumentHint: '[clear]' })
    return next(e)
  })

  on('command.run', { command: COMMAND }, (_$, e) => {
    if (/^\s*clear\s*$/i.test(e.args)) {
      log.clear()
      return { text: 'Log cleared.' }
    }
    return { text: formatLog(log.events) }
  })

  // Every tool: refuse paths to secret files, then replace secrets in whatever the tool returns.
  on('tool.call', async ($, e, next) => {
    const input = e as unknown as Record<string, unknown>
    const hit = PATH_FIELDS.map(k => input[k]).find(v => typeof v === 'string' && isSecretPath(v))
    if (hit) {
      await record($, { action: 'blocked', tool: e.tool, where: whereOf(e.tool, input), why: 'the path is a shell config or credential file' })
      return { deny: `${$.plugin.name}: ${String(hit)} is a shell config or credential file. ${ELSEWHERE}` }
    }

    const out = await next(e)
    if (out.deny !== undefined) return out
    const { value, count, kinds } = redactValue(out.result)
    if (count === 0) return out
    await record($, { action: 'redacted', tool: e.tool, where: whereOf(e.tool, input), kinds, lines: redactedLines(value) })
    // Stays up until the user's next prompt (cleared below). Names the kinds, never the values.
    $.ui.status(`secret-guard redacted ${count} secret${count === 1 ? '' : 's'} from ${e.tool} output: ${describeKinds(kinds)} · /${COMMAND} for details`)
    return { result: value as typeof out.result, context: out.context }
  }).catch(($, e, next) =>
    next.called
      ? { deny: `${$.plugin.name}: output redaction failed, so the result was withheld.` }
      : { deny: `${$.plugin.name}: its guard failed, so the tool call was blocked.` },
  )

  on('tool.call', { tool: 'Bash' }, async ($, e, next) => {
    const verdict = bashVerdict(e.command)
    if (verdict.kind === 'allow') return next(e)
    const where = whereOf('Bash', e as unknown as Record<string, unknown>)
    if (verdict.kind === 'deny') {
      await record($, { action: 'blocked', tool: 'Bash', where, why: verdict.reason })
      $.ui.status(`secret-guard blocked a command: ${verdict.reason} · /${COMMAND} for details`)
      return { deny: `${$.plugin.name}: blocked, ${verdict.reason}. ${ELSEWHERE}` }
    }

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
    const allowed = answer === ALLOW
    await record($, { action: allowed ? 'asked, allowed' : 'asked, blocked', tool: 'Bash', where, why: verdict.reason })
    return allowed ? next(e) : { deny: `${$.plugin.name}: the user did not allow this command (it ${verdict.reason}). ${ELSEWHERE}` }
  }).catch(($, e, next) => (next.called ? next(e) : { deny: `${$.plugin.name}: its guard failed, so the command was blocked.` }))

  // The status note is about the last turn: the user's next prompt clears it.
  on('prompt.submit', ($, e, next) => {
    $.ui.status(undefined)
    return next(e)
  })
}
