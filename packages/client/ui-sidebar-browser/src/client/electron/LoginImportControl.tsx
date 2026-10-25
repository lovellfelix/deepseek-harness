/** Saved-login importer for the Electron Browser carrier; coexists with the Web profile's iframe carrier. */
import { useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import type { BrowserBodyProps } from '../view/BrowserBody.tsx'
import type { DesktopBrowserLoginBridge, DesktopBrowserLoginSource, DesktopBrowserLoginUnavailableReason } from '../../types.ts'
import css from '../view/Browser.module.css'

/** Props supplied by the Browser chrome that owns the toolbar and page controller. */
export interface LoginImportControlProps {
  /** Shell operations for reading a browser profile and importing its cookies. */
  readonly bridge: DesktopBrowserLoginBridge
  /** Localized copy owned by the Browser dictionary. */
  readonly t: BrowserBodyProps['t']
  /** Called after a successful import so the page can reload with the new session. */
  readonly onImported: () => void
}

/** One unavailable reason mapped to its catalogued copy. */
function unavailableCopy(t: LoginImportControlProps['t'], reason: DesktopBrowserLoginUnavailableReason): string {
  switch (reason) {
    case 'unsupported-platform': return t('login.error.unsupported-platform')
    case 'unsupported-browser': return t('login.error.unsupported-browser')
    case 'no-browser-tab': return t('login.error.no-browser-tab')
    case 'unreadable': return t('login.error.unreadable')
    case 'keychain': return t('login.error.keychain')
    default: return t('login.error.unexpected')
  }
}

/** List saved browser profiles and import one profile's cookies into open Browser sessions. */
export function LoginImportControl({ bridge, t, onImported }: LoginImportControlProps): ReactNode {
  const [sources, setSources] = useState<readonly DesktopBrowserLoginSource[]>()
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState<string>()
  useEffect(() => {
    let current = true
    void bridge.loginSources().then(
      next => { if (current) setSources(next) },
      () => { if (current) setNotice(t('login.error.unexpected')) },
    )
    return () => { current = false }
  }, [bridge, t])
  const importLogins = async (source: DesktopBrowserLoginSource): Promise<void> => {
    setBusy(true)
    setNotice(undefined)
    try {
      const result = await bridge.importLogins(source.id)
      if (result.status === 'imported') {
        setNotice(result.skipped + result.failed > 0
          ? t('login.imported.partial', { label: result.label, imported: String(result.imported), left: String(result.skipped + result.failed) })
          : t('login.imported', { label: result.label, imported: String(result.imported) }))
        onImported()
      } else {
        setNotice(unavailableCopy(t, result.reason))
      }
    } catch {
      setNotice(t('login.error.unexpected'))
    } finally {
      setBusy(false)
    }
  }
  return (
    <section className={css.loginPanel} aria-label={t('login.title')}>
      <p className={css.loginHeading}>{t('login.title')}</p>
      <p className={css.loginHint}>{t('login.description')}</p>
      {sources === undefined
        ? <p className={css.loginHint}>{t('login.loading')}</p>
        : sources.length === 0
          ? <p className={css.loginHint}>{t('login.empty')}</p>
          : <div className={css.loginList}>{sources.map(source => <button
            key={source.id}
            type="button"
            className={css.loginSource}
            disabled={busy}
            onClick={() => { void importLogins(source) }}
          >{source.label}</button>)}</div>}
      {notice !== undefined && <p className={css.loginNotice} role="status">{notice}</p>}
    </section>
  )
}
