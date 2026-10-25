import { createCipheriv, createHash, pbkdf2Sync } from 'node:crypto'
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { afterEach, describe, expect, it } from 'vitest'
import {
  decodeChromiumCookieValue,
  describeChromiumSources,
  importChromiumCookies,
  listChromiumProfiles,
  readChromiumCookieDatabase,
  toChromiumCookieDetails,
  type ChromiumCookieRow,
} from '../src/chromium-cookies.ts'

const PASSWORD = 'test-safe-storage-password'
const homes: string[] = []

afterEach(() => {
  for (const home of homes.splice(0)) rmSync(home, { recursive: true, force: true })
})

/** Encrypt one cookie the way macOS Chromium does: PBKDF2-SHA1 key, AES-128-CBC, v10 prefix. */
function encryptCookieValue(hostKey: string, value: string): Buffer {
  const key = pbkdf2Sync(PASSWORD, 'saltysalt', 1003, 16, 'sha1')
  const plaintext = Buffer.concat([createHash('sha256').update(hostKey).digest(), Buffer.from(value, 'utf8')])
  const cipher = createCipheriv('aes-128-cbc', key, Buffer.alloc(16, 0x20))
  return Buffer.concat([Buffer.from('v10'), cipher.update(plaintext), cipher.final()])
}

/** Create a fake Chrome user-data tree with one schema-24 cookie database. */
function fakeChromeHome(): string {
  const home = mkdtempSync(join(tmpdir(), 'dsh-chromium-test-'))
  homes.push(home)
  const network = join(home, 'Library', 'Application Support', 'Google', 'Chrome', 'Default', 'Network')
  mkdirSync(network, { recursive: true })
  const database = new DatabaseSync(join(network, 'Cookies'))
  database.exec(`
    CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
    INSERT INTO meta VALUES ('version', '24');
    CREATE TABLE cookies (host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB, path TEXT,
      expires_utc INTEGER, is_secure INTEGER, is_httponly INTEGER, samesite INTEGER,
      has_expires INTEGER, is_persistent INTEGER, top_frame_site_key TEXT);
  `)
  const expiresUtc = (Date.now() + 86_400_000) * 1_000 + 11_644_473_600_000_000
  const insert = database.prepare('INSERT INTO cookies VALUES (?,?,?,?,?,?,?,?,?,?,?,?)')
  insert.run('.example.com', 'sid', '', encryptCookieValue('.example.com', 'session-token'), '/', expiresUtc, 1, 1, 1, 1, 1, '')
  insert.run('legacy.example', 'pref', 'plain-value', '', '/', 0, 0, 0, -1, 0, 0, '')
  insert.run('.partitioned.example', 'p', '', encryptCookieValue('.partitioned.example', 'x'), '/', expiresUtc, 1, 0, 1, 1, 1, 'https://top.example')
  database.close()
  return home
}

/** Minimal session double that records imported details. */
function fakeSession(): { session: Parameters<typeof importChromiumCookies>[0][number]; writes: unknown[] } {
  const writes: unknown[] = []
  return {
    writes,
    session: { cookies: { set: async (details: unknown) => { writes.push(details) }, flushStore: async () => {} } } as unknown as Parameters<typeof importChromiumCookies>[0][number],
  }
}

describe('chromium cookie import', () => {
  it('discovers browser profiles under the macOS Application Support tree', () => {
    const home = fakeChromeHome()
    const profiles = listChromiumProfiles(home)
    expect(profiles).toHaveLength(1)
    expect(profiles[0]?.browser).toBe('chrome')
    expect(profiles[0]?.profileName).toBe('Default')
    expect(describeChromiumSources(profiles)).toEqual([{ id: 'chrome:Google/Chrome:Default', label: 'Google Chrome — Default' }])
  })

  it('reads schema 24 cookies through a staged copy with safe numbers', () => {
    const database = readChromiumCookieDatabase(listChromiumProfiles(fakeChromeHome())[0]!)
    expect(database?.schemaVersion).toBe(24)
    expect(database?.cookies).toHaveLength(3)
    expect(Number.isSafeInteger(database?.cookies[0]?.expiresUtc)).toBe(true)
    expect(database?.cookies[0]?.partitioned).toBe(false)
    expect(database?.cookies[2]?.partitioned).toBe(true)
  })

  it('decrypts v10 values and enforces the schema-24 host binding', () => {
    const profile = listChromiumProfiles(fakeChromeHome())[0]!
    const database = readChromiumCookieDatabase(profile)!
    const row = database.cookies[0]!
    expect(decodeChromiumCookieValue(row.encryptedValue!, row.hostKey, database.schemaVersion, PASSWORD)).toBe('session-token')
    expect(() => decodeChromiumCookieValue(row.encryptedValue!, 'other.example', database.schemaVersion, PASSWORD))
      .toThrow(/host binding/u)
  })

  it('maps cookie rows to Electron details and rejects unfaithful cookies', () => {
    const row: ChromiumCookieRow = {
      hostKey: '.example.com', name: 'sid', value: '', encryptedValue: undefined, path: '/',
      expiresUtc: 11_644_473_600_000_000 + 2_000_000_000 * 1_000_000, secure: true, httpOnly: true,
      sameSite: 1, hasExpires: true, persistent: true, partitioned: false,
    }
    expect(toChromiumCookieDetails(row, 'session-token')).toEqual({
      url: 'https://example.com/',
      name: 'sid',
      value: 'session-token',
      path: '/',
      secure: true,
      httpOnly: true,
      sameSite: 'lax',
      domain: '.example.com',
      expirationDate: 2_000_000_000,
    })
    expect(toChromiumCookieDetails({ ...row, partitioned: true }, 'x')).toBeUndefined()
    expect(toChromiumCookieDetails({ ...row, name: '__Host-sid' }, 'x')).toBeUndefined()
    expect(toChromiumCookieDetails({ ...row, expiresUtc: 11_644_473_600_000_000 }, 'x')).toBeUndefined()
    expect(toChromiumCookieDetails({ ...row, name: 'big', value: 'x'.repeat(5_000) }, 'x'.repeat(5_000))).toBeUndefined()
  })

  it.skipIf(process.platform !== 'darwin')('imports one profile into every open Browser session and reports counts', async () => {
    const profile = listChromiumProfiles(fakeChromeHome())[0]!
    const first = fakeSession()
    const second = fakeSession()
    const result = await importChromiumCookies([first.session, second.session], profile, { readPassword: async () => PASSWORD })
    expect(result).toEqual({ status: 'imported', label: 'Google Chrome — Default', imported: 2, skipped: 1, failed: 0 })
    expect(first.writes).toHaveLength(2)
    expect(second.writes).toHaveLength(2)
    expect(first.writes).toEqual(second.writes)
  })

  it.skipIf(process.platform !== 'darwin')('reports unavailable states without throwing', async () => {
    const profile = listChromiumProfiles(fakeChromeHome())[0]!
    const denied = await importChromiumCookies([fakeSession().session], profile, { readPassword: async () => undefined })
    expect(denied).toEqual({ status: 'unavailable', reason: 'keychain' })
    const noTab = await importChromiumCookies([], profile, { readPassword: async () => PASSWORD })
    expect(noTab).toEqual({ status: 'unavailable', reason: 'no-browser-tab' })
  })
})
