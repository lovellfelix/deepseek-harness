/**
 * Import saved cookies from a Chromium-family browser into the Sidebar Browser guests.
 *
 * macOS Chromium stores cookie values with the OS Safe Storage key: the encrypted
 * `v10` blob is AES-128-CBC over `PBKDF2-HMAC-SHA1(safeStoragePassword, "saltysalt", 1003, 16)`
 * with sixteen space bytes as the IV. The Safe Storage password itself is a generic
 * Keychain item owned by the browser, so reading it prompts the operator and is only
 * attempted after an explicit import request.
 */

import { execFile } from 'node:child_process'
import { createDecipheriv, createHash, pbkdf2Sync } from 'node:crypto'
import { copyFileSync, existsSync, mkdtempSync, readdirSync, rmSync } from 'node:fs'
import { createRequire } from 'node:module'
import { homedir, tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Session } from 'electron'
import type { DesktopBrowserLoginImportResult, DesktopBrowserLoginSource } from '@deepseek-ai/dsh-client-ui-sidebar-browser/types'

/** Chromium browsers whose Safe Storage keys this importer understands on macOS. */
export type ChromiumBrowserId = 'chrome' | 'brave' | 'edge' | 'arc' | 'chromium'

/** One importer definition: user-data roots and the browser's Safe Storage identity. */
export interface ChromiumBrowserDefinition {
  readonly id: ChromiumBrowserId
  readonly label: string
  readonly keychainService: string
  readonly keychainAccount: string
  /** User-data directories below `~/Library/Application Support`, in display order. */
  readonly userDataDirectories: readonly string[]
}

/** One discovered Chromium profile that may hold a cookie database. */
export interface ChromiumProfile {
  /** Stable identity for one profile occurrence across browser and user-data root. */
  readonly id: string
  readonly browser: ChromiumBrowserId
  readonly browserLabel: string
  readonly userDataRoot: string
  readonly profileName: string
  readonly cookieDatabasePath: string
}

/** Raw persisted cookie row read from the SQLite database. */
export interface ChromiumCookieRow {
  readonly hostKey: string
  readonly name: string
  readonly value: string
  readonly encryptedValue: Uint8Array | undefined
  readonly path: string
  readonly expiresUtc: number
  readonly secure: boolean
  readonly httpOnly: boolean
  readonly sameSite: number
  readonly hasExpires: boolean
  readonly persistent: boolean
  readonly partitioned: boolean
}

/** Cookie values plus the database schema version that produced them. */
export interface ChromiumCookieDatabase {
  readonly schemaVersion: number
  readonly cookies: readonly ChromiumCookieRow[]
}

/** Cookie fields Electron accepts for one `session.cookies.set` call. */
export interface ChromiumCookieDetails {
  readonly url: string
  readonly name: string
  readonly value: string
  readonly path: string
  readonly secure: boolean
  readonly httpOnly: boolean
  readonly sameSite: 'unspecified' | 'no_restriction' | 'lax' | 'strict'
  readonly domain?: string
  readonly expirationDate?: number
}

/** Chromium-family browsers and the user-data roots they use on macOS. */
export const CHROMIUM_BROWSER_DEFINITIONS: readonly ChromiumBrowserDefinition[] = [
  {
    id: 'chrome',
    label: 'Google Chrome',
    keychainService: 'Chrome Safe Storage',
    keychainAccount: 'Chrome',
    userDataDirectories: ['Google/Chrome', 'Google/Chrome Beta', 'Google/Chrome Dev', 'Google/Chrome Canary'],
  },
  {
    id: 'brave',
    label: 'Brave',
    keychainService: 'Brave Safe Storage',
    keychainAccount: 'Brave',
    userDataDirectories: ['BraveSoftware/Brave-Browser'],
  },
  {
    id: 'edge',
    label: 'Microsoft Edge',
    keychainService: 'Microsoft Edge Safe Storage',
    keychainAccount: 'Microsoft Edge',
    userDataDirectories: ['Microsoft Edge'],
  },
  {
    id: 'arc',
    label: 'Arc',
    keychainService: 'Arc Safe Storage',
    keychainAccount: 'Arc',
    userDataDirectories: ['Arc/User Data'],
  },
  {
    id: 'chromium',
    label: 'Chromium',
    keychainService: 'Chromium Safe Storage',
    keychainAccount: 'Chromium',
    userDataDirectories: ['Chromium'],
  },
]

/** A Chromium cookie value is never larger than 4096 bytes. */
const MAX_COOKIE_BYTES = 4096

/** Safe Storage key derivation parameters shared by every macOS Chromium browser. */
const SAFE_STORAGE_ITERATIONS = 1003
const SAFE_STORAGE_SALT = 'saltysalt'
const SAFE_STORAGE_KEY_LENGTH = 16

/** Chromium's epoch starts in 1601; Electron cookie expiry uses Unix seconds. */
const CHROMIUM_EPOCH_OFFSET_SECONDS = 11_644_473_600

/** Run at most this many cookie writes concurrently. */
const COOKIE_WRITE_CONCURRENCY = 8

/** SQLite bindings shipped with Electron's Node; typed locally so the shell compiles without sqlite type declarations. */
interface SqliteStatement {
  get(...parameters: readonly unknown[]): Record<string, unknown> | undefined
  all(...parameters: readonly unknown[]): Record<string, unknown>[]
}

interface SqliteDatabase {
  prepare(sql: string): SqliteStatement
  close(): void
}

interface SqliteModule {
  readonly DatabaseSync: new (path: string, options?: { readonly readOnly?: boolean }) => SqliteDatabase
}

const SQLITE_MODULE = 'node:sqlite'

/**
 * List browser profiles that hold a cookie database.
 * @param homeDirectory - operator home directory, overridable for tests.
 * @returns every detected profile in browser and user-data-root order.
 */
export function listChromiumProfiles(homeDirectory: string = homedir()): ChromiumProfile[] {
  const applicationSupport = join(homeDirectory, 'Library', 'Application Support')
  const profiles: ChromiumProfile[] = []
  for (const definition of CHROMIUM_BROWSER_DEFINITIONS) {
    for (const userDataRoot of definition.userDataDirectories) {
      const root = join(applicationSupport, userDataRoot)
      const profileNames = chromiumProfileNames(root)
      for (const profileName of profileNames) {
        const cookieDatabasePath = cookieDatabaseIn(join(root, profileName))
        if (cookieDatabasePath === undefined) continue
        profiles.push({
          id: `${definition.id}:${userDataRoot}:${profileName}`,
          browser: definition.id,
          browserLabel: definition.label,
          userDataRoot,
          profileName,
          cookieDatabasePath,
        })
      }
    }
  }
  return profiles
}

/**
 * Present detected profiles as import choices.
 * @param profiles - profiles discovered by {@link listChromiumProfiles}.
 * @returns bridge-safe source descriptors.
 */
export function describeChromiumSources(profiles: readonly ChromiumProfile[]): DesktopBrowserLoginSource[] {
  return profiles.map(profile => ({
    id: profile.id,
    label: `${profile.browserLabel} — ${profile.profileName}`,
  }))
}

/**
 * Read one browser's cookie database through a private staged copy.
 * @param profile - profile whose cookie database should be read.
 * @returns schema version and raw rows, or `undefined` when the database is unreadable.
 */
export function readChromiumCookieDatabase(profile: ChromiumProfile): ChromiumCookieDatabase | undefined {
  const staged = stagingDirectory()
  let database: SqliteDatabase | undefined
  try {
    for (const file of ['Cookies', 'Cookies-wal', 'Cookies-shm']) {
      const source = file === 'Cookies' ? profile.cookieDatabasePath : `${profile.cookieDatabasePath}${file.slice('Cookies'.length)}`
      if (file !== 'Cookies' && !existsSync(source)) continue
      if (!existsSync(source)) return undefined
      copyFileSync(source, join(staged, file))
    }
    const { DatabaseSync } = sqlite()
    database = new DatabaseSync(join(staged, 'Cookies'), { readOnly: true })
    const versionRow = database.prepare('SELECT value FROM meta WHERE key = ?').get('version')
    const schemaVersion = typeof versionRow?.value === 'string' ? Number(versionRow.value) : 0
    // Microseconds since 1601 exceed Number.MAX_SAFE_INTEGER; seconds precision is all a cookie
    // expiry needs, so read the column as a double instead of letting SQLite throw on the integer.
    const rows = database.prepare([
      'SELECT host_key, name, value, encrypted_value, path, CAST(expires_utc AS REAL) AS expires_utc,',
      'is_secure, is_httponly, samesite, has_expires, is_persistent, top_frame_site_key',
      'FROM cookies',
    ].join(' ')).all()
    return { schemaVersion: Number.isFinite(schemaVersion) ? schemaVersion : 0, cookies: rows.map(toCookieRow) }
  } catch (error) {
    console.warn('desktop browser login import: cookie database unreadable', error)
    return undefined
  } finally {
    try { database?.close() } catch { /* A failed close must not hide the original read failure. */ }
    rmSync(staged, { recursive: true, force: true })
  }
}

/**
 * Decrypt one stored cookie value.
 * @param encryptedValue - raw `encrypted_value` blob.
 * @param hostKey - cookie host; schema versions at or above 24 bind the host inside the plaintext.
 * @param schemaVersion - database `meta.version`.
 * @param safeStoragePassword - browser Safe Storage password.
 * @param derivation - cached PBKDF2 key factory, reused across one import.
 * @returns the plaintext cookie value.
 */
export function decodeChromiumCookieValue(
  encryptedValue: Uint8Array,
  hostKey: string,
  schemaVersion: number,
  safeStoragePassword: string,
  derivation: (password: string) => Buffer = safeStorageKey,
): string {
  const blob = Buffer.from(encryptedValue)
  if (blob.length <= 3 || blob.subarray(0, 3).toString('utf8') !== 'v10') {
    throw new Error('desktop browser login import: unsupported cookie encryption')
  }
  const key = derivation(safeStoragePassword)
  try {
    const decipher = createDecipheriv('aes-128-cbc', key, Buffer.alloc(16, 0x20))
    let plaintext = Buffer.concat([decipher.update(blob.subarray(3)), decipher.final()])
    if (schemaVersion >= 24) {
      const expected = createHash('sha256').update(hostKey).digest()
      if (plaintext.length < expected.length || !plaintext.subarray(0, expected.length).equals(expected)) {
        throw new Error('desktop browser login import: cookie host binding does not match')
      }
      plaintext = plaintext.subarray(expected.length)
    }
    const value = plaintext.toString('utf8')
    plaintext.fill(0)
    return value
  } finally {
    key.fill(0)
  }
}

/**
 * Map one database row plus its decrypted value to Electron cookie details.
 * @param cookie - persisted row.
 * @param value - decrypted cookie value.
 * @param nowSeconds - current Unix time, injected for tests.
 * @returns details for `session.cookies.set`, or `undefined` when the cookie cannot be imported faithfully.
 */
export function toChromiumCookieDetails(
  cookie: ChromiumCookieRow,
  value: string,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): ChromiumCookieDetails | undefined {
  if (cookie.partitioned || cookie.hostKey.length === 0 || cookie.name.length === 0) return undefined
  if (Buffer.byteLength(cookie.name) + Buffer.byteLength(value) > MAX_COOKIE_BYTES) return undefined
  const expirationDate = cookie.persistent && cookie.hasExpires && cookie.expiresUtc > 0
    ? Math.floor(cookie.expiresUtc / 1_000_000) - CHROMIUM_EPOCH_OFFSET_SECONDS
    : undefined
  if (expirationDate !== undefined && expirationDate <= nowSeconds) return undefined
  const host = cookie.hostKey.replace(/^\./, '')
  if (host.length === 0) return undefined
  const path = cookie.path.startsWith('/') ? cookie.path : `/${cookie.path}`
  const urlHost = host.includes(':') && !host.startsWith('[') ? `[${host}]` : host
  const sameSite = SAME_SITE[cookie.sameSite] ?? 'unspecified'
  if (sameSite === 'no_restriction' && !cookie.secure) return undefined
  if (cookie.name.startsWith('__Host-') && (!cookie.secure || path !== '/' || cookie.hostKey.startsWith('.'))) return undefined
  const details: ChromiumCookieDetails = {
    url: `${cookie.secure ? 'https' : 'http'}://${urlHost}${path}`,
    name: cookie.name,
    value,
    path,
    secure: cookie.secure,
    httpOnly: cookie.httpOnly,
    sameSite,
    ...(cookie.hostKey.startsWith('.') ? { domain: cookie.hostKey } : {}),
    ...(expirationDate === undefined ? {} : { expirationDate }),
  }
  return details
}

/**
 * Read a browser's Safe Storage password from the login Keychain.
 * @param definition - browser to read for.
 * @returns the password, or `undefined` when the item is missing or access was refused.
 */
export async function readSafeStoragePassword(definition: ChromiumBrowserDefinition): Promise<string | undefined> {
  if (process.platform !== 'darwin') return undefined
  try {
    const stdout = await new Promise<string>((resolve, reject) => {
      execFile('/usr/bin/security', [
        'find-generic-password', '-q', '-a', definition.keychainAccount, '-s', definition.keychainService, '-w',
      ], { timeout: 60_000, encoding: 'utf8' }, (error, output) => {
        if (error === null) resolve(output)
        else reject(error)
      })
    })
    const password = stdout.replace(/\n$/u, '')
    return password.length === 0 ? undefined : password
  } catch {
    return undefined
  }
}

/** Test seams for the import pipeline; production calls omit them. */
export interface ChromiumCookieImportOptions {
  /** @returns the browser Safe Storage password, or `undefined` when unavailable. */
  readonly readPassword?: (definition: ChromiumBrowserDefinition) => Promise<string | undefined>
}

/**
 * Import one Chromium profile's cookies into the given Electron sessions.
 * @param sessions - Sidebar Browser sessions that should receive the saved logins.
 * @param profile - profile whose cookies are imported.
 * @param options - test seams; production calls omit them.
 * @returns an import result safe to surface in the Browser UI.
 */
export async function importChromiumCookies(
  sessions: readonly Session[],
  profile: ChromiumProfile,
  options: ChromiumCookieImportOptions = {},
): Promise<DesktopBrowserLoginImportResult> {
  const label = `${profile.browserLabel} — ${profile.profileName}`
  if (process.platform !== 'darwin') return { status: 'unavailable', reason: 'unsupported-platform' }
  if (sessions.length === 0) return { status: 'unavailable', reason: 'no-browser-tab' }
  const definition = CHROMIUM_BROWSER_DEFINITIONS.find(candidate => candidate.id === profile.browser)
  if (definition === undefined) return { status: 'unavailable', reason: 'unsupported-browser' }
  const database = readChromiumCookieDatabase(profile)
  if (database === undefined) return { status: 'unavailable', reason: 'unreadable' }
  const password = await (options.readPassword ?? readSafeStoragePassword)(definition)
  if (password === undefined) return { status: 'unavailable', reason: 'keychain' }
  const keyCache = new Map<string, Buffer>()
  const derivation = (value: string): Buffer => {
    const cached = keyCache.get(value)
    if (cached !== undefined) return cached
    const key = safeStorageKey(value)
    keyCache.set(value, key)
    return key
  }
  let imported = 0
  let skipped = 0
  let failed = 0
  const rows: ChromiumCookieDetails[] = []
  for (const cookie of database.cookies) {
    // Partitioned cookies carry a top-level-site binding Electron 44 cannot restore; skip them cheaply.
    if (cookie.partitioned) { skipped += 1; continue }
    let value = cookie.value
    if (cookie.encryptedValue !== undefined && cookie.encryptedValue.length > 0) {
      try {
        value = decodeChromiumCookieValue(cookie.encryptedValue, cookie.hostKey, database.schemaVersion, password, derivation)
      } catch {
        failed += 1
        continue
      }
    }
    const details = toChromiumCookieDetails(cookie, value)
    if (details === undefined) { skipped += 1; continue }
    rows.push(details)
  }
  try {
    for (let index = 0; index < rows.length; index += COOKIE_WRITE_CONCURRENCY) {
      const batch = rows.slice(index, index + COOKIE_WRITE_CONCURRENCY)
      const results = await Promise.allSettled(sessions.map(async session => {
        for (const details of batch) await session.cookies.set(details as Parameters<Session['cookies']['set']>[0])
      }))
      for (const result of results) if (result.status === 'rejected') failed += batch.length
      if (results.every(result => result.status === 'fulfilled')) imported += batch.length
    }
    await Promise.allSettled(sessions.map(session => session.cookies.flushStore()))
  } finally {
    for (const key of keyCache.values()) key.fill(0)
  }
  return { status: 'imported', label, imported, skipped, failed }
}

/** Derive the Safe Storage AES key from a browser password. */
function safeStorageKey(password: string): Buffer {
  return pbkdf2Sync(password, SAFE_STORAGE_SALT, SAFE_STORAGE_ITERATIONS, SAFE_STORAGE_KEY_LENGTH, 'sha1')
}

/** Profile directory names Chromium creates; only directories that carry a cookie database are returned. */
function chromiumProfileNames(root: string): string[] {
  if (!existsSync(root)) return []
  const names: string[] = []
  try {
    for (const entry of readdirSync(root, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue
      if (entry.name === 'Default' || entry.name === 'Guest Profile' || entry.name === 'System Profile'
        || /^Profile [0-9]+$/u.test(entry.name)) names.push(entry.name)
    }
  } catch {
    return []
  }
  names.sort((left, right) => profileOrder(left) - profileOrder(right))
  return names
}

/** Order profiles for display: Default first, then numeric Profile directories, then special profiles. */
function profileOrder(name: string): number {
  if (name === 'Default') return 0
  const match = /^Profile ([0-9]+)$/u.exec(name)
  if (match !== null) return Number(match[1]) + 1
  return 1000
}

/** Find the cookie database inside one profile directory, honoring the post-Chrome-96 layout. */
function cookieDatabaseIn(profileDirectory: string): string | undefined {
  const candidates = [join(profileDirectory, 'Network', 'Cookies'), join(profileDirectory, 'Cookies')]
  return candidates.find(candidate => existsSync(candidate))
}

/** Create a private staging directory for the cookie database copy. */
function stagingDirectory(): string {
  return mkdtempSync(join(tmpdir(), 'dsh-chromium-cookies-'))
}

/** Load Electron's bundled SQLite bindings. */
function sqlite(): SqliteModule {
  const require = createRequire(import.meta.url)
  return require(SQLITE_MODULE) as SqliteModule
}

/** Map one raw SQLite row with defensive coercion. */
function toCookieRow(row: Record<string, unknown>): ChromiumCookieRow {
  const encrypted = row.encrypted_value
  return {
    hostKey: String(row.host_key ?? ''),
    name: String(row.name ?? ''),
    value: String(row.value ?? ''),
    encryptedValue: encrypted instanceof Uint8Array ? encrypted : undefined,
    path: String(row.path ?? '/'),
    expiresUtc: Number(row.expires_utc ?? 0),
    secure: Number(row.is_secure ?? 0) !== 0,
    httpOnly: Number(row.is_httponly ?? 0) !== 0,
    sameSite: Number(row.samesite ?? -1),
    hasExpires: Number(row.has_expires ?? 0) !== 0,
    persistent: Number(row.is_persistent ?? 0) !== 0,
    partitioned: String(row.top_frame_site_key ?? '').length > 0,
  }
}

/** Chromium SameSite enum to Electron value; unspecified (-1) stays implicit. */
const SAME_SITE: Readonly<Record<number, ChromiumCookieDetails['sameSite']>> = {
  [-1]: 'unspecified',
  0: 'no_restriction',
  1: 'lax',
  2: 'strict',
}
