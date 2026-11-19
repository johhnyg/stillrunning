import { atom, read, update } from 'claude-code'
import type { EngineInterface, Register } from 'claude-code'

import type {
  Counts,
  Cve,
  CvePanel,
  CveVuln,
  Decision,
  Finding,
  Guard,
  Scan,
  Shield,
  Tally,
  View,
} from '../types'

const PANE = 'stillrunning-shield'
const TITLE = 'stillrunning shield'
const REFRESH_MS = 5000
// Without a change in the hook's files, the panel re-reads this often.
const IDLE_REFRESH_MS = 5 * 60 * 1000
const STALE_HOURS = 48
// Known-vulnerability data older than this is not proof of anything.
const CVE_FRESH_S = 24 * 3600
const RESCAN_AFTER_S = 12 * 3600
const MAX_PASSES = 12

const shield = atom(
  { plugin: 'stillrunning-shield', key: 'shield' } as const,
  null,
  { shape: 'shield-5' },
)
const guard = atom(
  { plugin: 'stillrunning-shield', key: 'guard' } as const,
  null,
  { shape: 'guard-1' },
)
const cvePanel = atom(
  { plugin: 'stillrunning-shield', key: 'cve' } as const,
  { data: null, busy: false, readFailed: false } as CvePanel,
  { shape: 'cve-1' },
)
const view = atom(
  { plugin: 'stillrunning-shield', key: 'view' } as const,
  {
    page: 'main',
    since: null,
    cwd: null,
    wasOn: false,
    offSince: null,
    announced: 0,
    scanning: false,
  } as View,
  { shape: 'view-2' },
)

const LABEL: Record<string, { mark: string; word: string; color?: string }> = {
  no_known_threat: { mark: '✓', word: 'no known threat', color: 'green' },
  blocked: { mark: '✗', word: 'BLOCKED', color: 'red' },
  needs_approval: { mark: '⚠', word: "Couldn't check · your call", color: 'yellow' },
  override: { mark: '•', word: 'Allowed by you', color: 'yellow' },
  note: { mark: '•', word: 'Not looked up' },
}
const UNKNOWN = { mark: '⚠', word: "Couldn't check · your call", color: 'yellow' }

const num = (v: unknown): number | null =>
  typeof v === 'number' && Number.isFinite(v) ? v : null
const str = (v: unknown, max: number): string =>
  typeof v === 'string' ? v.slice(0, max) : ''
const obj = (v: unknown): Record<string, unknown> =>
  v && typeof v === 'object' ? (v as Record<string, unknown>) : {}
const plural = (n: number, one: string, many = `${one}s`) =>
  `${n.toLocaleString('en-US')} ${n === 1 ? one : many}`

function counts(v: unknown): Counts | null {
  const o = obj(v)
  const checked = num(o.checked)
  const blocked = num(o.blocked)
  const needsApproval = num(o.needs_approval)
  if (checked === null || blocked === null || needsApproval === null) return null

  return { checked, blocked, needsApproval }
}

function decision(v: unknown): Decision | null {
  const o = obj(v)
  const ts = num(o.ts)
  const subject = str(o.subject, 120)
  if (ts === null || !subject) return null
  const evidence = Array.isArray(o.evidence)
    ? o.evidence
        .map(e => str(obj(e).text, 200))
        .filter(Boolean)
        .slice(0, 5)
    : []

  return {
    ts,
    verdict: str(o.verdict, 32),
    subject,
    isPackage: typeof o.name === 'string' && o.name.length > 0,
    command: str(o.command, 420) || null,
    cmdId: /^[0-9a-f]{32}$/.test(str(o.cmd_id, 33)) ? str(o.cmd_id, 32) : null,
    canRemember: o.can_remember === true,
    explanation: str(o.explanation, 600) || null,
    evidence,
  }
}

function problem(text: string): Shield {
  return {
    problem: text,
    hook: 'unknown',
    today: null,
    week: null,
    blocklistSize: null,
    blocklistAgeHours: null,
    decisions: [],
    remembered: [],
  }
}

/** Turns the output of `stillrunning shield --json` into what the pane draws. */
export function parse(stdout: string): Shield {
  let raw: unknown
  try {
    raw = JSON.parse(stdout)
  } catch {
    return problem('The stillrunning report could not be read (not JSON).')
  }
  const o = obj(raw)
  if (o.schema !== 1) {
    return problem(
      'This panel does not understand this version of the stillrunning report. Update the panel or stillrunning.',
    )
  }
  const blocklist = obj(o.blocklist)

  return {
    problem: null,
    hook: str(o.hook, 24) || 'unknown',
    today: counts(o.today),
    week: counts(o.week),
    blocklistSize: num(blocklist.size),
    blocklistAgeHours: num(blocklist.age_hours),
    decisions: (Array.isArray(o.decisions) ? o.decisions : [])
      .map(decision)
      .filter((d): d is Decision => d !== null)
      .slice(0, 200),
    remembered: [],
  }
}

const KINDS = ['blocked', 'suspicious', 'some_versions']
// What the scan may show of a package: names and versions in the shapes the
// registries allow, nothing else.
const NAME = /^(@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/i
const VERSION = /^[a-z0-9][a-z0-9.+!_-]{0,40}$/i

function finding(v: unknown): Finding | null {
  const o = obj(v)
  const name = str(o.name, 100)
  const kind = str(o.kind, 20)
  if (!NAME.test(name) || !KINDS.includes(kind)) return null
  const version = str(o.version, 41)

  return {
    where: o.where === 'installed' ? 'installed' : 'project',
    file: str(o.file, 80),
    eco: o.eco === 'npm' ? 'npm' : 'pip',
    name,
    version: VERSION.test(version) ? version : null,
    kind: kind as Finding['kind'],
    advisory: /^[A-Za-z0-9][A-Za-z0-9._:-]{2,63}$/.test(str(o.advisory, 64))
      ? str(o.advisory, 64)
      : null,
    listedSince: /^\d{4}-\d{2}-\d{2}$/.test(str(o.listed_since, 10))
      ? str(o.listed_since, 10)
      : null,
    badVersions: (Array.isArray(o.bad_versions) ? o.bad_versions : [])
      .map(x => str(x, 41))
      .filter(x => VERSION.test(x))
      .slice(0, 6),
  }
}

function tally(v: unknown): Tally {
  const o = obj(v)

  return { total: num(o.total) ?? 0, checked: num(o.checked) ?? 0 }
}

/** Turns the output of `stillrunning panel --json` into a Guard, or null. */
export function parseGuard(stdout: string): Guard | null {
  let raw: unknown
  try {
    raw = JSON.parse(stdout)
  } catch {
    return null
  }
  const o = obj(raw)
  if (o.schema !== 1) return null
  const p = obj(o.protection)
  const s = o.scan ? obj(o.scan) : null
  const scan: Scan | null = s
    ? {
        scannedAt: num(s.scanned_at) ?? 0,
        files: (Array.isArray(s.manifests) ? s.manifests : [])
          .map(m => ({
            file: str(obj(m).file, 80),
            packages: num(obj(m).packages) ?? 0,
            unreadable: obj(m).unreadable === true,
          }))
          .filter(m => m.file)
          .slice(0, 40),
        project: tally(s.project),
        installed: tally(s.installed),
        findings: (Array.isArray(s.findings) ? s.findings : [])
          .map(finding)
          .filter((f): f is Finding => f !== null),
        partial: s.partial === true,
        listConfirmedFresh: s.list_confirmed_fresh === true,
      }
    : null

  return {
    state: p.state === 'on' ? 'on' : p.state === 'off' ? 'off' : 'unknown',
    problems: (Array.isArray(p.problems) ? p.problems : [])
      .map(x => str(x, 300))
      .filter(Boolean)
      .slice(0, 4),
    scan,
  }
}

/** What a finding means and what to do about it, in fixed plain words. */
export function tell(f: Finding): { why: string; todo: string } {
  const since = f.listedSince ? ` since ${f.listedSince}` : ''
  const id = f.advisory ? ` (${f.advisory})` : ''
  if (f.kind === 'some_versions') {
    return {
      why: `Some versions are listed as malicious: ${f.badVersions.join(', ') || 'see Details'}${id}.`,
      todo:
        f.where === 'installed'
          ? 'Check which version is installed and upgrade if it is one of these.'
          : `Pin a version that is not one of these in ${f.file}.`,
    }
  }
  if (f.kind === 'suspicious') {
    return {
      why: `Flagged as suspicious${since}${id}.`,
      todo: 'Look at what it does before using it.',
    }
  }
  if (f.where === 'installed') {
    return {
      why: `Already installed here, and listed as malicious${since}${id}.`,
      todo: 'Uninstall it, then treat passwords and keys on this machine as exposed and change them.',
    }
  }

  return {
    why: `Listed as malicious${since}${id}.`,
    todo: `Remove it from ${f.file} before anything installs it.`,
  }
}

// What the CVE report may show: ids, versions, names, severity words and a
// few fixed sentences from the client, each matched against a strict pattern.
const VULN_ID = /^[A-Z][A-Z0-9]{1,15}-[A-Za-z0-9][A-Za-z0-9._:-]{1,60}$/
const PLACE = /^[A-Za-z0-9 ._/@+-]{1,120}$/
const SENTENCE = /^[A-Za-z0-9 .,:;()'/_+-]{1,240}$/
const SEVERITIES = ['LOW', 'MODERATE', 'HIGH', 'CRITICAL', 'MALICIOUS'] as const
// a saved time further ahead than this is a clock problem, not proof
const FUTURE_SLACK_S = 120
const sev = (v: unknown): CveVuln['severity'] =>
  (SEVERITIES as readonly string[]).includes(v as string) ? (v as CveVuln['severity']) : null

/**
 * Turns the output of `stillrunning cve --json` into a Cve, or null. The
 * panel re-derives the state from the details for its own folder (`cwd`):
 * green only when every part of the proof is there.
 */
export function parseCve(stdout: string, now = Date.now() / 1000, cwd: string | null = null): Cve | null {
  let raw: unknown
  try {
    raw = JSON.parse(stdout)
  } catch {
    return null
  }
  const o = obj(raw)
  if (o.schema !== 1 || !['CLEAR', 'AFFECTED', 'UNKNOWN'].includes(o.state as string)) return null
  const c = obj(o.counts)
  const rawAffected = Array.isArray(o.affected) ? o.affected : []
  let dropped = 0
  const affected = rawAffected
    .map(a => {
      const x = obj(a)
      const name = str(x.name, 214)
      const version = str(x.version, 41)
      if (!NAME.test(name) || !VERSION.test(version)) return null
      const rawVulns = Array.isArray(x.vulns) ? x.vulns : []
      const vulns = rawVulns
        .map(v => {
          const y = obj(v)
          const id = str(y.id, 80)
          const fixed = str(y.fixed, 41)
          const known = y.severity === null || y.severity === undefined || sev(y.severity) !== null
          return VULN_ID.test(id) && known
            ? { id, severity: sev(y.severity), fixed: VERSION.test(fixed) ? fixed : null }
            : null
        })
        .filter((v): v is CveVuln => v !== null)
        .slice(0, 20)
      if (vulns.length !== Math.min(rawVulns.length, 20)) dropped += 1
      if (vulns.length === 0) return null

      return {
        eco: x.eco === 'npm' ? 'npm' : 'pip',
        name,
        version,
        where: (Array.isArray(x.where) ? x.where : [])
          .map(w => str(w, 120))
          .filter(w => PLACE.test(w))
          .slice(0, 6),
        vulns,
      }
    })
    .filter((a): a is Cve['affected'][number] => a !== null)
  dropped += rawAffected.length - affected.length
  const feedUpdatedAt = num(o.feed_updated_at)
  const refreshedAt = num(o.refreshed_at)
  let state = o.state as Cve['state']
  const reasons = (Array.isArray(o.reasons) ? o.reasons : [])
    .map(r => str(r, 240))
    .filter(r => SENTENCE.test(r))
    .slice(0, 6)
  const unknown = (why: string) => {
    state = 'UNKNOWN'
    if (!reasons.includes(why)) reasons.push(why)
  }
  const parts = (Array.isArray(o.inventory) ? o.inventory : []).map(p => {
    const x = obj(p)
    const why = str(x.why, 300)
    return {
      part: str(x.part, 120),
      kind: str(x.kind, 20),
      resolved: num(x.resolved) ?? -1,
      unresolved: num(x.unresolved) ?? -1,
      why: why && SENTENCE.test(why) ? why : null,
    }
  })
  const goodParts = parts.filter(
    p => PLACE.test(p.part) && ['project file', 'installed', 'search'].includes(p.kind)
      && p.resolved >= 0 && p.unresolved >= 0,
  )
  const root = str(o.root, 400)
  // The panel holds its own line: the report must be for this folder, its
  // times must not lie ahead, a feed that aged past a day is not proof any
  // more, and CLEAR needs every part of the proof in the details.
  if (cwd !== null && root !== cwd) unknown('Checked for another folder.')
  if ([feedUpdatedAt, refreshedAt].some(t => t !== null && t > now + FUTURE_SLACK_S)) {
    unknown('The saved time is in the future.')
  }
  if (dropped > 0 || goodParts.length !== parts.length) unknown('The CVE report did not add up.')
  if (state === 'CLEAR') {
    const failures = Array.isArray(o.failures) ? o.failures.length : 1
    if (feedUpdatedAt === null || now - feedUpdatedAt > CVE_FRESH_S) {
      unknown('The feed is older than 24h.')
    } else if (
      goodParts.length === 0 || goodParts.some(p => p.unresolved > 0)
      || (num(c.resolved) ?? 0) <= 0 || num(c.not_checked) !== 0 || failures !== 0
      || affected.length > 0
    ) {
      unknown('Not everything here could be checked.')
    }
  }
  if (state === 'AFFECTED' && affected.length === 0) state = 'UNKNOWN'
  const critical = affected.filter(a => a.vulns.some(v => v.severity === 'CRITICAL')).length
  const malicious = affected.filter(a => a.vulns.some(v => v.severity === 'MALICIOUS')).length
  const rank = (s: CveVuln['severity']) => (s ? SEVERITIES.indexOf(s) + 1 : 0)
  const worst = affected
    .flatMap(a => a.vulns.map(v => v.severity))
    .reduce<CveVuln['severity']>((m, s) => (rank(s) > rank(m) ? s : m), null)

  return {
    state,
    reasons,
    root: /^\/[A-Za-z0-9 ._/@+-]{0,400}$/.test(root) ? root : null,
    refreshedAt,
    feedUpdatedAt,
    affectedPackages: affected.length,
    critical,
    malicious,
    worst,
    parts: goodParts.slice(0, 40),
    affected,
  }
}

/** Colour of the CVE line: green only for CLEAR, red with a critical. */
export function cveTone(c: Cve | null): 'green' | 'red' | 'yellow' {
  if (!c || c.state === 'UNKNOWN') return 'yellow'
  if (c.state === 'CLEAR') return 'green'

  return c.critical > 0 || c.malicious > 0 ? 'red' : 'yellow'
}

/** Colour of one Details row: a critical is red, any other severity amber. */
export const vulnTone = (s: CveVuln['severity']): 'red' | 'yellow' =>
  s === 'CRITICAL' || s === 'MALICIOUS' ? 'red' : 'yellow'

/** "CVEs · 2 affected deps (1 critical) · feed updated 3h ago". */
export function cveLine(p: CvePanel): string {
  const c = p.data
  if (!c) {
    return p.readFailed
      ? 'CVEs · unknown · the CVE report could not be read'
      : 'CVEs · unknown · not read yet'
  }
  const fresh = c.reasons.includes('Checked for another folder.')
    ? 'checked for another folder'
    : c.reasons.includes('The saved time is in the future.')
      ? 'feed time in the future'
      : c.feedUpdatedAt !== null
        ? `feed updated ${ago(c.feedUpdatedAt)}`
        : c.refreshedAt === null
          ? 'feed never refreshed'
          : 'feed unreachable'
  const n = c.affectedPackages
  const detail =
    c.state === 'AFFECTED'
      ? `${n} affected dep${n === 1 ? '' : 's'} (${
          [c.critical > 0 ? `${c.critical} critical` : '', c.malicious > 0 ? `${c.malicious} malicious` : '']
            .filter(Boolean)
            .join(', ') || `worst ${(c.worst ?? 'unknown').toLowerCase()}`
        })`
      : c.state === 'CLEAR'
        ? 'clear'
        : 'unknown'

  return `CVEs · ${detail} · ${fresh}`
}

/** What to do about one vulnerability, in fixed words. */
export const cveTodo = (v: CveVuln) =>
  v.severity === 'MALICIOUS'
    ? 'listed as malicious — remove it (the blocklist refuses it)'
    : v.fixed
      ? `upgrade to ${v.fixed}`
      : 'no fixed version is known yet'

async function readCve($: EngineInterface): Promise<void> {
  let data: Cve | null = null
  const v = await read($, view)
  const argv = ['stillrunning', 'cve', '--json']
  if (v.cwd) argv.push('--cwd', v.cwd)
  try {
    // local state only: this never fetches anything
    const ran = await $.process.run(argv, { timeoutMs: 8000 })
    data = ran.exitCode === 0 ? parseCve(ran.stdout, Date.now() / 1000, v.cwd) : null
  } catch {
    data = null
  }
  await update($, cvePanel, was => ({ ...was, data, readFailed: data === null }))
}

/** The explicit "Refresh CVE data" button: the one panel action that fetches. */
async function refreshCve($: EngineInterface): Promise<void> {
  const p = await read($, cvePanel)
  if (p.busy) return
  await update($, cvePanel, was => ({ ...was, busy: true }))
  const v = await read($, view)
  const argv = ['stillrunning', 'cve', '--refresh']
  if (v.cwd) argv.push('--cwd', v.cwd)
  try {
    await $.process.run(argv, { timeoutMs: 200000 })
  } catch {
    // the state file says what happened; read it below
  } finally {
    await update($, cvePanel, was => ({ ...was, busy: false }))
  }
  await readCve($)
  const now = await read($, cvePanel)
  void $.ui.toast(`stillrunning: ${cveLine(now)}`, { timeoutMs: 8000 })
}

// Each refresh starts the stillrunning command, which costs most of a second
// of CPU. So the timer only looks at two small files, and a refresh runs when
// one of them changed (the hook wrote a decision, or the Claude Code settings
// that hold the hook were edited), after a Bash call, or every few minutes.
let seenStats = ''
let seenSettings = ''
let seenCve = ''
let ticksSinceRefresh = 0

async function fileText($: EngineInterface, path: string): Promise<string> {
  try {
    return String(await $.fs.read(path))
  } catch {
    return '(unreadable)'
  }
}

async function tick($: EngineInterface): Promise<void> {
  const home = (await $.env.get('HOME')) ?? ''
  const stats = await fileText($, `${home}/.stillrunning/hook_stats.json`)
  const settings = await fileText($, `${home}/.claude/settings.json`)
  // written by `stillrunning cve --refresh` (the scheduled job or the button)
  const cveState = await fileText($, `${home}/.stillrunning/cve_state.json`)
  ticksSinceRefresh += 1
  const idle = ticksSinceRefresh * REFRESH_MS >= IDLE_REFRESH_MS
  if (stats === seenStats && settings === seenSettings && cveState === seenCve && !idle) return
  seenStats = stats
  seenSettings = settings
  seenCve = cveState
  await refresh($)
}

let scanBusy = false
let scanAgainAt = 0

async function readGuard($: EngineInterface, scan: boolean): Promise<Guard | null> {
  const v = await read($, view)
  const argv = ['stillrunning', 'panel', '--json']
  if (scan) argv.push('--scan')
  if (v.cwd) argv.push('--cwd', v.cwd)
  try {
    const ran = await $.process.run(argv, { timeoutMs: scan ? 120000 : 8000 })

    return ran.exitCode === 0 ? parseGuard(ran.stdout) : null
  } catch {
    return null
  }
}

/**
 * Checks this project's and this machine's packages. The site limits how
 * fast names can be looked up, so a scan runs in passes until nothing is
 * left or a pass makes no progress.
 */
async function scanNow($: EngineInterface): Promise<void> {
  if (scanBusy) return
  scanBusy = true
  await update($, view, v => ({ ...v, scanning: true }))
  try {
    let before = -1
    for (let pass = 0; pass < MAX_PASSES; pass += 1) {
      const g = await readGuard($, true)
      if (!g || !g.scan) break
      await update($, guard, () => g)
      const done = g.scan.project.checked + g.scan.installed.checked
      if (!g.scan.partial || done <= before) break
      before = done
    }
    const g = await read($, guard)
    const bad = g?.scan?.findings.filter(f => f.kind === 'blocked').length ?? 0
    if (bad > 0) {
      void $.ui.toast(
        `stillrunning: ${plural(bad, 'package')} here ${bad === 1 ? 'is' : 'are'} on the threat list`,
        { timeoutMs: 10000 },
      )
    }
  } finally {
    scanBusy = false
    scanAgainAt = Date.now() + 10 * 60 * 1000
    await update($, view, v => ({ ...v, scanning: false }))
  }
}

/** Ids of remembered commands; none when the list cannot be read. */
async function rememberedIds($: EngineInterface): Promise<string[]> {
  try {
    const ran = await $.process.run(
      ['stillrunning', 'remember', '--list', '--json'],
      { timeoutMs: 8000 },
    )
    if (ran.exitCode !== 0) return []
    const rows = obj(JSON.parse(ran.stdout)).commands

    return (Array.isArray(rows) ? rows : [])
      .map(r => str(obj(r).id, 32))
      .filter(id => /^[0-9a-f]{32}$/.test(id))
  } catch {
    return []
  }
}

/**
 * "Don't ask again" for one exact command. The client decides whether that
 * is allowed (never a blocked package or a change to the protection); the
 * panel only passes the id on and shows the answer.
 */
async function rememberCommand($: EngineInterface, cmdId: string): Promise<void> {
  let said = 'stillrunning could not remember that command.'
  try {
    const ran = await $.process.run(
      ['stillrunning', 'remember', cmdId, '--json'],
      { timeoutMs: 8000 },
    )
    const answer = obj(JSON.parse(ran.stdout))
    said =
      answer.ok === true
        ? "Remembered. You won't be asked again for that exact command."
        : `Not remembered. ${str(answer.reason, 240)}`
  } catch {
    // `said` already explains
  }
  void $.ui.toast(said, { timeoutMs: 9000 })
  await refresh($)
}

async function refresh($: EngineInterface): Promise<void> {
  ticksSinceRefresh = 0
  let next: Shield
  try {
    const ran = await $.process.run(
      ['stillrunning', 'shield', '--json', '-n', '200'],
      { timeoutMs: 8000 },
    )
    next =
      ran.exitCode === 0
        ? parse(ran.stdout)
        : problem(
            'stillrunning is installed but has no `shield` report. Update it: pip install -U stillrunning',
          )
  } catch {
    next = problem(
      'stillrunning was not found. Install it with: pip install stillrunning',
    )
  }
  if (!next.problem && next.decisions.some(d => d.canRemember)) {
    next = { ...next, remembered: await rememberedIds($) }
  }
  await update($, shield, () => next)
  await readCve($)

  // A block the person may not be looking at the panel for.
  const v = await read($, view)
  const fresh = next.decisions.filter(
    d => d.verdict === 'blocked' && d.ts > v.announced,
  )
  const newest = next.decisions.reduce((m, d) => Math.max(m, d.ts), v.announced)
  if (newest > v.announced) {
    await update($, view, was => ({ ...was, announced: newest }))
  }
  if (fresh.length > 0) {
    void $.ui.toast(
      fresh.length === 1
        ? `stillrunning blocked ${fresh[0]?.subject ?? 'an install'}`
        : `stillrunning blocked ${fresh.length} installs`,
      { timeoutMs: 8000 },
    )
  }

  if (scanBusy) return
  const g = await readGuard($, false)
  if (!g) return
  await update($, guard, () => g)

  // Protection that was on and no longer is: say so once, loudly.
  if (g.state === 'on') {
    if (!v.wasOn || v.offSince !== null) {
      await update($, view, was => ({ ...was, wasOn: true, offSince: null }))
    }
  } else if (g.state === 'off' && v.wasOn && v.offSince === null) {
    await update($, view, was => ({ ...was, offSince: Date.now() / 1000 }))
    void $.ui.toast(
      'stillrunning protection was switched off. Installs are no longer checked.',
      { timeoutMs: 15000 },
    )
  }

  const age = g.scan ? Date.now() / 1000 - g.scan.scannedAt : Infinity
  if ((age > RESCAN_AFTER_S || g.scan?.partial) && Date.now() > scanAgainAt) {
    void scanNow($)
  }
}

function clock(ts: number): string {
  const d = new Date(ts * 1000)
  const two = (n: number) => String(n).padStart(2, '0')

  return `${two(d.getHours())}:${two(d.getMinutes())}`
}

function ago(ts: number): string {
  const min = Math.max(0, Math.round((Date.now() / 1000 - ts) / 60))
  if (min < 1) return 'just now'
  if (min < 60) return `${min} min ago`
  if (min < 48 * 60) return `${Math.round(min / 60)}h ago`

  return `${Math.round(min / 1440)} days ago`
}

function age(hours: number | null): string {
  if (hours === null) return 'age unknown'
  if (hours < 1) return 'updated under an hour ago'
  if (hours < 48) return `updated about ${Math.round(hours)}h ago`

  return `updated about ${Math.round(hours / 24)} days ago`
}

type Group = { d: Decision; times: number }

/** Newest first; the same verdict on the same subject shows once, counted. */
export function group(list: Decision[]): Group[] {
  const seen = new Map<string, Group>()
  for (const d of list) {
    const key = `${d.verdict}\n${d.subject}\n${d.cmdId ?? d.command ?? ''}`
    const had = seen.get(key)
    if (had) had.times += 1
    else seen.set(key, { d, times: 1 })
  }

  return [...seen.values()]
}

/**
 * The long explanation, cut to a reason and what to do: its sentences without
 * the bracketed asides, less an opening "Blocked `x`." that the row repeats.
 */
export function brief(d: Decision): { why: string; todo: string | null } {
  const text = (d.explanation ?? d.evidence[0] ?? '')
    .replace(/\s*\([^)]*\)/g, '')
    .trim()
  if (!text) return { why: 'It could not be checked.', todo: null }
  const parts = text
    .split('. ')
    .map(s => s.trim())
    .filter(Boolean)
    .map(s => (/[.!?]$/.test(s) ? s : `${s}.`))
  if (parts.length > 1 && parts[0]?.startsWith('Blocked ')) parts.shift()
  const why = parts[0] ?? 'It could not be checked.'
  const todo = parts.length > 1 ? (parts[parts.length - 1] ?? null) : null

  return { why, todo }
}

const needsYou = (d: Decision) => d.verdict !== 'no_known_threat'

/**
 * The three outcomes, counted from the decision records so that every scope
 * uses one source: looked up and not on the list; could not be verified, so
 * a person decided; on the list.
 */
export type Three = { ok: number; unsure: number; blocked: number }
export function three(list: Decision[]): Three {
  const out = { ok: 0, unsure: 0, blocked: 0 }
  for (const d of list) {
    if (d.verdict === 'no_known_threat') out.ok += 1
    else if (d.verdict === 'blocked') out.blocked += 1
    else if (d.verdict === 'needs_approval') out.unsure += 1
  }

  return out
}

function midnight(): number {
  const d = new Date()
  d.setHours(0, 0, 0, 0)

  return d.getTime() / 1000
}

/** The command cut to `width`, keeping the package name in view. */
export function snippet(command: string, name: string, width: number): string {
  if (command.length <= width) return command
  const at = name ? command.indexOf(name) : -1
  if (at < 0 || at + name.length <= width - 1) {
    return `${command.slice(0, width - 1)}…`
  }
  const start = Math.max(
    0,
    Math.min(at - 12, command.length - (width - 2)),
  )
  const body = command.slice(start, start + width - 2)

  return `…${body}${start + width - 2 < command.length ? '…' : ''}`
}

export const register: Register = on => {
  on('session.start', async ($, e, next) => {
    await $.command.register({
      name: 'shield',
      description: 'Show what stillrunning checked and blocked, in a side panel',
    })
    const now = Date.now() / 1000
    await update($, view, v => ({
      ...v,
      since: v.since ?? now,
      announced: v.announced || now,
      cwd: e.cwd ?? v.cwd,
      scanning: false,
    }))
    void $.ui.open({ id: PANE, title: TITLE })
    void refresh($)
    $.clock.every(REFRESH_MS, () => void tick($))

    return next(e)
  })

  on('command.run', { command: 'shield' }, async $ => {
    await refresh($)
    await $.ui.open({ id: PANE, title: TITLE })

    return { text: 'stillrunning shield panel opened.' }
  })

  // The hook writes its decision before the command runs; read it again as
  // soon as the call ends so the panel moves with the chat.
  on('tool.call', { tool: 'Bash' }, async ($, e, next) => {
    try {
      return await next(e)
    } finally {
      void refresh($)
    }
  })

  on('ui.render', { component: 'Pane', requestId: PANE }, async ($, e) => {
    const { Box, Text, Button } = $.ui.resolve(e)
    const s = await read($, shield)
    const g = await read($, guard)
    const v = await read($, view)
    const cp = await read($, cvePanel)
    const cv = cp.data
    const cveCritical = cv?.state === 'AFFECTED' && (cv.critical > 0 || cv.malicious > 0)
    const cveRow = (
      <Text color={cveTone(cv)} wrap="wrap" bold={cveCritical}>
        {cveLine(cp)}
      </Text>
    )
    const go = (page: View['page']) => () =>
      void update($, view, was => ({ ...was, page }))
    const rescan = () => {
      scanAgainAt = 0
      void scanNow($)
    }

    if (!s) return <Text dimColor>Reading stillrunning…</Text>
    if (s.problem) {
      return (
        <Box flexDirection="column">
          <Text color="yellow" bold>
            ⚠ Not protecting yet
          </Text>
          <Text wrap="wrap">{s.problem}</Text>
        </Box>
      )
    }

    // The panel's own check of the settings file wins over the report's word.
    const hookOn = g ? g.state === 'on' : s.hook === 'active'
    const stale =
      s.blocklistAgeHours !== null && s.blocklistAgeHours > STALE_HOURS
    const rows = e.viewport?.rows ?? 30
    const scan = g?.scan ?? null
    const findings = scan?.findings ?? []
    const listed = findings.filter(f => f.kind === 'blocked')
    const row = (x: Group, withTime = true) => {
      const l = LABEL[x.d.verdict] ?? UNKNOWN

      return (
        <Text wrap="truncate-end">
          <Text color={l.color} bold={x.d.verdict === 'blocked'}>
            {l.mark} {l.word}
          </Text>
          {'  '}
          {x.d.subject}
          {x.times > 1 ? ` ×${x.times}` : ''}
          {withTime && <Text dimColor>  {ago(x.d.ts)}</Text>}
        </Text>
      )
    }
    const found = (f: Finding, full: boolean) => {
      const t = tell(f)
      const red = f.kind === 'blocked'

      return (
        <Box flexDirection="column">
          <Text wrap="truncate-end">
            <Text color={red ? 'red' : 'yellow'} bold={red}>
              {red ? '✗ On the threat list' : '⚠ Check this'}
            </Text>
            {'  '}
            {f.name}
            {f.version ? ` ${f.version}` : ''}
            <Text dimColor>
              {'  '}
              {f.where === 'installed' ? 'installed' : f.file}
            </Text>
          </Text>
          <Text wrap="wrap">  {t.why}</Text>
          {full && (
            <Text wrap="wrap" dimColor>
              {'  '}→ {t.todo}
            </Text>
          )}
        </Box>
      )
    }
    const part = (name: string, t: Tally, mine: Finding[], empty: string) => {
      if (t.total === 0) return <Text dimColor>{empty}</Text>
      const left = t.total - t.checked
      const bad = mine.filter(f => f.kind === 'blocked').length
      if (bad > 0) {
        return (
          <Text color="red">
            ✗ {name}: {plural(bad, 'package')} on the threat list
          </Text>
        )
      }
      if (left > 0) {
        return (
          <Text color="yellow" wrap="wrap">
            … {name}: {t.checked.toLocaleString('en-US')} of{' '}
            {plural(t.total, 'package')} checked
            {v.scanning ? ', still checking' : ', the rest could not be checked yet'}
          </Text>
        )
      }

      return (
        <Text color="green" wrap="wrap">
          ✓ {name}: {plural(t.total, 'package')}, none on the threat list
        </Text>
      )
    }

    if (v.page === 'details') {
      const all = group(s.decisions)
      const room = Math.max(3, rows - 22 - findings.length * 2)
      const t = three(s.decisions.filter(d => d.ts >= midnight()))
      const line = (name: string, c: Counts | null) => (
        <Text wrap="wrap">
          {name}: {c ? `${c.checked} packages looked at · ${c.needsApproval} couldn't check · ${c.blocked} blocked` : 'nothing recorded'}
        </Text>
      )

      return (
        <Box flexDirection="column">
          <Text bold>Details</Text>
          <Text wrap="wrap">
            Today: {t.ok} no known threat · {t.unsure} couldn't check · {t.blocked} blocked
          </Text>
          {line('Last 7 days', s.week)}
          <Text wrap="wrap">Claude Code hook: {hookOn ? 'on' : 'off'}</Text>
          <Text wrap="wrap" color={stale ? 'yellow' : undefined}>
            {s.blocklistSize === null
              ? 'Threat list: not downloaded yet'
              : `Threat list: ${s.blocklistSize.toLocaleString('en-US')} packages reported as malicious, ${age(s.blocklistAgeHours)}`}
          </Text>
          <Text> </Text>
          <Text bold>Scan of this project and machine</Text>
          {!scan && <Text dimColor>Not scanned yet.</Text>}
          {scan && (
            <Box flexDirection="column">
              <Text dimColor wrap="wrap">
                Scanned {ago(scan.scannedAt)}. Files read:{' '}
                {scan.files.length === 0
                  ? 'none found'
                  : scan.files
                      .map(m => `${m.file} (${m.unreadable ? 'could not be read' : m.packages})`)
                      .join(', ')}
              </Text>
              {findings.length === 0 && <Text dimColor>Nothing found.</Text>}
              {findings.slice(0, 8).map(f => found(f, true))}
              {findings.length > 8 && (
                <Text dimColor>…and {findings.length - 8} more: stillrunning panel</Text>
              )}
              {!scan.listConfirmedFresh && (
                <Text dimColor wrap="wrap">
                  The site did not say how fresh its list was for this scan.
                </Text>
              )}
              <Text dimColor wrap="wrap">
                Only package names are sent to stillrunning.io for a scan,
                never file contents.
              </Text>
            </Box>
          )}
          <Text> </Text>
          <Text bold>Known vulnerabilities (CVEs)</Text>
          {cveRow}
          {(cv?.reasons ?? []).map(r => (
            <Text color="yellow" wrap="wrap">
              ⚠ {r}
            </Text>
          ))}
          {cv && cv.affected.length === 0 && cv.state === 'AFFECTED' && (
            <Text dimColor>No details saved.</Text>
          )}
          {(cv?.affected ?? []).slice(0, 12).flatMap(a =>
            a.vulns.slice(0, 4).map(x => (
              <Box flexDirection="column">
                <Text color={vulnTone(x.severity)} wrap="wrap">
                  {vulnTone(x.severity) === 'red' ? '✗' : '⚠'} {a.name} {a.version}
                  {'  '}
                  {x.id} · {(x.severity ?? 'unknown severity').toLowerCase()}
                  {x.fixed ? ` · fixed in ${x.fixed}` : ' · no fix known'}
                </Text>
                <Text dimColor wrap="wrap">
                  {'  '}
                  {a.where.join(', ') || a.eco} → {cveTodo(x)}
                </Text>
              </Box>
            )),
          )}
          {(cv?.affected.length ?? 0) > 12 && (
            <Text dimColor>…and {(cv?.affected.length ?? 0) - 12} more: stillrunning cve</Text>
          )}
          {cv && cv.parts.length > 0 && (
            <Text dimColor wrap="wrap">
              Inventory:{' '}
              {cv.parts
                .map(p => `${p.part} ${p.resolved}${p.unresolved ? `, ${p.unresolved} not resolved${p.why ? ` (${p.why})` : ''}` : ''}`)
                .join(' · ')}
            </Text>
          )}
          <Text dimColor wrap="wrap">
            This shortens the time to patch known bugs in packages already here.
            It does not detect malware or stop attacks, and covers only what
            OSV.dev knows. A refresh sends package names, ecosystems and
            versions to api.osv.dev, never file contents or paths.
          </Text>
          <Button key="cve-refresh" onPress={() => void refreshCve($)}>
            {cp.busy ? 'Refreshing CVE data…' : 'Refresh CVE data'}
          </Button>
          <Text> </Text>
          <Text bold>Remembered commands</Text>
          <Text dimColor wrap="wrap">
            {s.remembered.length === 0
              ? 'None. You are asked about every "your call" command.'
              : `${s.remembered.length} exact command${s.remembered.length === 1 ? '' : 's'} you chose not to be asked about again. See them: stillrunning remember --list · undo: stillrunning forget <id>`}
          </Text>
          <Text> </Text>
          <Text bold>History</Text>
          {all.length === 0 && <Text dimColor>Nothing recorded yet.</Text>}
          {all.slice(0, room).map(x => row(x))}
          {all.length > room && (
            <Text dimColor>…and {all.length - room} more: stillrunning shield</Text>
          )}
          <Text> </Text>
          <Text dimColor wrap="wrap">
            "None on the threat list" and "no known threat" mean the name is
            not on the list of packages reported as malicious. It is not a
            guarantee: a brand-new harmful package may not be listed yet.
          </Text>
          <Text> </Text>
          <Button key="back" onPress={go('main')}>Back</Button>
        </Box>
      )
    }

    const since = v.since ?? 0
    const mine = s.decisions.filter(d => d.ts >= since)
    const sess = three(mine)
    const day = three(s.decisions.filter(d => d.ts >= midnight()))
    const columns = Math.max(24, (e.props?.bodyColumns ?? 56) - 6)
    // Fixed-width columns so the rows line up in a screenshot: the label,
    // then each count right-aligned in the same width on every row.
    const width = Math.max(2, ...[sess, day].flatMap(t => [t.ok, t.unsure, t.blocked])
      .map(n => String(n).length))
    const n = (v: number) => String(v).padStart(width)
    const scope = (name: string, t: Three) => (
      <Text wrap="truncate-end">
        <Text dimColor>{name.padEnd(13)}</Text>
        <Text color={t.ok > 0 ? 'green' : undefined} dimColor={t.ok === 0}>
          ✓ {n(t.ok)}
        </Text>
        <Text dimColor>   </Text>
        <Text color={t.unsure > 0 ? 'yellow' : undefined} dimColor={t.unsure === 0}>
          ⚠ {n(t.unsure)}
        </Text>
        <Text dimColor>   </Text>
        <Text color={t.blocked > 0 ? 'red' : undefined} dimColor={t.blocked === 0}>
          ✗ {n(t.blocked)}
        </Text>
      </Text>
    )
    const rule = <Text dimColor>{'─'.repeat(Math.min(columns, 48))}</Text>
    // What needs a look, for the amber headline: held installs this session,
    // problems with the hook's own setup, and a stale threat list.
    // An affected package without a critical vulnerability also needs a look;
    // one with a critical turns the headline red (below).
    const cveEyes = cv?.state === 'AFFECTED' && !cveCritical ? cv.affectedPackages : 0
    const eyes = sess.unsure + (g?.problems ?? []).length + (stale ? 1 : 0) + cveEyes
    const flagged = group(mine.filter(needsYou))
    const room = Math.max(1, Math.floor((rows - 16 - findings.length * 3) / 4))
    const shown = findings.slice(0, 3)

    return (
      <Box flexDirection="column">
        {v.offSince !== null && !hookOn ? (
          <Box flexDirection="column">
            <Text color="red" bold>
              ✗ Protection was switched off {ago(v.offSince)}
            </Text>
            <Text wrap="wrap">
              Installs are no longer checked. If you did not do this, something
              on this machine changed your Claude Code settings. Turn it back
              on in a terminal: stillrunning --hook-claude-code
            </Text>
          </Box>
        ) : !hookOn ? (
          <Box flexDirection="column">
            <Text color="yellow" bold>
              ⚠ Not protecting Claude Code yet
            </Text>
            <Text wrap="wrap">
              Switch it on in a terminal: stillrunning --hook-claude-code
            </Text>
          </Box>
        ) : listed.length > 0 ? (
          <Text color="red" bold>
            ✗ Threat here · {plural(listed.length, 'package')} on the threat list
          </Text>
        ) : sess.blocked > 0 ? (
          <Text color="red" bold>
            ✗ Threat blocked · {sess.blocked}
            {eyes > 0 ? <Text color="yellow"> · ⚠ needs your eyes · {eyes}</Text> : ''}
          </Text>
        ) : cveCritical ? (
          <Text color="red" bold>
            {(cv?.malicious ?? 0) > 0
              ? `✗ Listed as malicious · ${plural(cv?.malicious ?? 0, 'package')} to remove`
              : `✗ Critical CVE · ${plural(cv?.critical ?? 0, 'package')} to patch`}
            {eyes > 0 ? <Text color="yellow"> · ⚠ needs your eyes · {eyes}</Text> : ''}
          </Text>
        ) : eyes > 0 ? (
          <Text color="yellow" bold>
            ⚠ Needs your eyes · {eyes}
          </Text>
        ) : (
          <Text>
            <Text color="green" bold>🛡 Protected</Text>
            <Text dimColor>
              {sess.ok > 0 ? ` · ${sess.ok} checked, no known threat` : ' · nothing to check yet'}
            </Text>
          </Text>
        )}
        {hookOn &&
          (g?.problems ?? []).map(p => (
            <Text color="yellow" wrap="wrap">
              ⚠ {p}
            </Text>
          ))}
        {rule}
        <Text dimColor>{''.padEnd(13)}✓ no known threat · ⚠ couldn't check · ✗ blocked</Text>
        {scope('This session', sess)}
        {scope('Today', day)}
        {stale && (
          <Text color="yellow" wrap="wrap">
            ⚠ The threat list was last {age(s.blocklistAgeHours)}: newer threats may be missing.
          </Text>
        )}
        {rule}
        {flagged.length === 0 && mine.length === 0 && (
          <Text dimColor wrap="wrap">
            No installs yet this session. When Claude installs a package, the
            result shows up here.
          </Text>
        )}
        {flagged.slice(0, room).map(x => {
          const b = brief(x.d)

          return (
            <Box flexDirection="column">
              {row(x)}
              {x.d.command && (
                <Text wrap="truncate-end" dimColor>
                  {'  '}$ {snippet(x.d.command, x.d.isPackage ? x.d.subject.split(' ')[0] ?? '' : '', columns)}
                </Text>
              )}
              <Text wrap="wrap">  {b.why}</Text>
              {b.todo && (
                <Text wrap="wrap" dimColor>
                  {'  '}→ {b.todo}
                </Text>
              )}
              {x.d.cmdId && s.remembered.includes(x.d.cmdId) && (
                <Text color="green" wrap="wrap">
                  {'  '}✓ Remembered: you won't be asked again for this exact
                  command. Its packages are still checked every time.
                </Text>
              )}
              {x.d.cmdId && x.d.canRemember && !s.remembered.includes(x.d.cmdId) && (
                <Button
                  key={`remember-${x.d.cmdId}`}
                  onPress={() => void rememberCommand($, x.d.cmdId ?? '')}
                >
                  Don't ask again for this exact command
                </Button>
              )}
              <Text> </Text>
            </Box>
          )
        })}
        {flagged.length > room && (
          <Text dimColor>…and {flagged.length - room} more in Details</Text>
        )}
        {rule}
        <Text bold>Already here</Text>
        {cveRow}
        {!scan && (
          <Text dimColor wrap="wrap">
            {v.scanning
              ? 'Checking this project and what is installed…'
              : 'Not scanned yet.'}
          </Text>
        )}
        {scan && (
          <Box flexDirection="column">
            {part(
              'This project',
              scan.project,
              findings.filter(f => f.where === 'project'),
              'This project: no dependency files found',
            )}
            {part(
              'Installed',
              scan.installed,
              findings.filter(f => f.where === 'installed'),
              'Installed: nothing found to check',
            )}
            {scan.files
              .filter(m => m.unreadable)
              .map(m => (
                <Text color="yellow" wrap="wrap">
                  ⚠ {m.file} could not be read, so it was not checked.
                </Text>
              ))}
            {shown.map(f => found(f, true))}
            {findings.length > shown.length && (
              <Text dimColor>
                …and {findings.length - shown.length} more in Details
              </Text>
            )}
            <Text dimColor>
              {v.scanning ? 'Checking now…' : `Checked ${ago(scan.scannedAt)}`}
            </Text>
          </Box>
        )}
        {rule}
        <Box flexDirection="row" gap={2}>
          <Button key="scan" onPress={rescan}>
            {v.scanning ? 'Scanning…' : 'Scan again'}
          </Button>
          <Button key="details" onPress={go('details')}>Details</Button>
          <Button key="refresh" onPress={() => void refresh($)}>Refresh</Button>
        </Box>
      </Box>
    )
  })
}
