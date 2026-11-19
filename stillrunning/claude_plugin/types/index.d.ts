export type Decision = {
  ts: number
  verdict: string
  subject: string
  /** True when the decision was about a named package that was looked at. */
  isPackage: boolean
  /** The command that was held or checked, credentials already removed. */
  command: string | null
  /** Identity of the exact command in its folder; null on older records. */
  cmdId: string | null
  /** The hook's word on whether this command may be remembered. */
  canRemember: boolean
  explanation: string | null
  evidence: string[]
}

export type Counts = { checked: number; blocked: number; needsApproval: number }

/** What the hook did. `problem` is set when the report could not be read. */
export type Shield = {
  problem: string | null
  hook: string
  today: Counts | null
  week: Counts | null
  blocklistSize: number | null
  blocklistAgeHours: number | null
  decisions: Decision[]
  /** Ids of the commands the person chose not to be asked about again. */
  remembered: string[]
}

export type Finding = {
  where: 'project' | 'installed'
  file: string
  eco: string
  name: string
  version: string | null
  kind: 'blocked' | 'suspicious' | 'some_versions'
  advisory: string | null
  listedSince: string | null
  badVersions: string[]
}

export type Tally = { total: number; checked: number }

export type Scan = {
  scannedAt: number
  files: { file: string; packages: number; unreadable: boolean }[]
  project: Tally
  installed: Tally
  findings: Finding[]
  partial: boolean
  listConfirmedFresh: boolean
}

/** Is the hook in place, and what the last scan of this project found. */
export type Guard = {
  state: 'on' | 'off' | 'unknown'
  problems: string[]
  scan: Scan | null
}

/** One known vulnerability of one package (ids, versions, severity words only). */
export type CveVuln = {
  id: string
  severity: 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL' | 'MALICIOUS' | null
  fixed: string | null
}

export type CveAffected = {
  eco: string
  name: string
  version: string
  where: string[]
  vulns: CveVuln[]
}

/** `stillrunning cve --json`: known vulnerabilities in packages already here. */
export type Cve = {
  state: 'CLEAR' | 'AFFECTED' | 'UNKNOWN'
  reasons: string[]
  root: string | null
  refreshedAt: number | null
  feedUpdatedAt: number | null
  affectedPackages: number
  critical: number
  /** Packages OSV lists as malicious (MAL- records). */
  malicious: number
  worst: CveVuln['severity']
  parts: { part: string; kind: string; resolved: number; unresolved: number; why: string | null }[]
  affected: CveAffected[]
}

/** The CVE data as last read, and whether an explicit refresh is running. */
export type CvePanel = { data: Cve | null; busy: boolean; readFailed: boolean }

/**
 * The page shown, when this session's count began (seconds), the project
 * folder, whether the hook was ever seen on, when it was seen switched off,
 * the newest decision already announced, and whether a scan is running.
 */
export type View = {
  page: 'main' | 'details'
  since: number | null
  cwd: string | null
  wasOn: boolean
  offSince: number | null
  announced: number
  scanning: boolean
}

declare module 'claude-code' {
  interface PluginState {
    'stillrunning-shield': {
      shield: Shaped<Shield | null>
      guard: Shaped<Guard | null>
      view: Shaped<View>
      cve: Shaped<CvePanel>
    }
  }
}
