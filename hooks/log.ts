// What secret-guard did this session, for /secret-guard. Holds only redacted text: kinds,
// rule names and lines with the values already replaced, never a secret.

import { MARK, describeKinds, redactText, type Kinds } from './redact'

export type Event =
  | { at: number; action: 'redacted'; tool: string; where: string; kinds: Kinds; lines: string[] }
  | { at: number; action: 'blocked' | 'asked, allowed' | 'asked, blocked'; tool: string; where: string; why: string }

const MAX_EVENTS = 50
const MAX_LINE = 160

/** A one-line, redacted summary of what a tool was called on: its command, file or pattern. */
export function whereOf(tool: string, input: Record<string, unknown>): string {
  const target = ['command', 'file_path', 'path', 'notebook_path', 'url', 'pattern'].map(k => input[k]).find(v => typeof v === 'string')
  const text = typeof target === 'string' ? redactText(target).text.replace(/\s+/g, ' ').trim() : ''
  return text ? `${tool} \`${clip(text)}\`` : tool
}

/** Up to three lines of a redacted result that held a secret, values already replaced. */
export function redactedLines(value: unknown, max = 3): string[] {
  const out: string[] = []
  const walk = (v: unknown) => {
    if (out.length >= max) return
    if (typeof v === 'string') {
      for (const line of v.split('\n')) {
        if (out.length >= max) return
        if (line.includes(MARK)) out.push(clip(line.trim()))
      }
    } else if (Array.isArray(v)) v.forEach(walk)
    else if (v !== null && typeof v === 'object') Object.values(v).forEach(walk)
  }
  walk(value)
  return out
}

function clip(s: string): string {
  return s.length > MAX_LINE ? `${s.slice(0, MAX_LINE)}…` : s
}

/** A session log, newest last, capped at 50 events. */
export function createLog() {
  const events: Event[] = []
  return {
    add(e: Event) {
      events.push(e)
      if (events.length > MAX_EVENTS) events.shift()
    },
    clear() {
      events.length = 0
    },
    get events(): readonly Event[] {
      return events
    },
  }
}

function clock(at: number): string {
  const d = new Date(at)
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}`
}

/** The /secret-guard report, newest first. */
export function formatLog(events: readonly Event[], limit = 20): string {
  if (events.length === 0) return 'Nothing redacted or blocked this session.'
  const shown = events.slice(-limit).reverse()
  const head = `${events.length} event${events.length === 1 ? '' : 's'} this session${events.length > limit ? `, newest ${limit} shown` : ''} (newest first). Values are never shown.`
  const rows = shown.map((e, i) => {
    const n = `${i + 1}.`.padEnd(4)
    if (e.action === 'redacted') {
      const count = Object.values(e.kinds).reduce((a, b) => a + b, 0)
      return [
        `${n}${clock(e.at)}  redacted ${count} secret${count === 1 ? '' : 's'} from ${e.tool} output`,
        `    where: ${e.where}`,
        `    what:  ${describeKinds(e.kinds, 8)}`,
        ...e.lines.map((l, j) => `    ${j === 0 ? 'lines:' : '      '} ${l}`),
      ].join('\n')
    }
    return [`${n}${clock(e.at)}  ${e.action}: ${e.where}`, `    why:   ${e.why}`].join('\n')
  })
  return [head, '', ...rows, '', 'Run /secret-guard clear to empty this log.'].join('\n')
}
