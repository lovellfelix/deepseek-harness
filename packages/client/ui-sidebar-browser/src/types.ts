/** Type-only Electron bridge declarations shared by the desktop shell and browser provider. */
import type { Branded } from '@deepseek-ai/dsh-brand'

/** Main-issued identity of one guest reservation. */
export type DesktopBrowserLeaseId = Branded<'DesktopBrowserLeaseId'>

/** A guest's approved, process-local storage partition. */
export interface DesktopBrowserReservation {
  readonly lease: DesktopBrowserLeaseId
  readonly partition: string
}

/** Main-approved request to open an HTTP(S) page from an existing guest. */
export interface DesktopBrowserOpenRequest {
  readonly lease: DesktopBrowserLeaseId
  readonly url: string
}

/** Origin-scoped operations; no Electron objects or arbitrary IPC cross this interface. */
export interface DesktopBrowserBridge {
  /** @param workspace - resolved storage account. @returns one approved guest reservation. */
  acquire(workspace: string): Promise<DesktopBrowserReservation>
  /** @param lease - the caller's reservation. @returns after its guest has been destroyed. */
  release(lease: DesktopBrowserLeaseId): Promise<void>
  /** @param lease - originating guest. @param listener - approved URL consumer. @returns unsubscribe callback. */
  onOpenRequested(lease: DesktopBrowserLeaseId, listener: (url: string) => void): () => void
  /**
   * Saved browser logins, when the shell carries a login importer.
   * Optional so an older shell still satisfies this bridge contract.
   */
  readonly login?: DesktopBrowserLoginBridge
}

/** One saved chromium-browser login store offered to the Browser tabs. */
export interface DesktopBrowserLoginSource {
  /** Opaque source identity interpreted by the Desktop shell. */
  readonly id: string
  /** Localized-ready browser and profile name, such as `Google Chrome — Default`. */
  readonly label: string
}

/** Unavailable reason for a login import request. */
export type DesktopBrowserLoginUnavailableReason =
  | 'unsupported-platform'
  | 'unsupported-browser'
  | 'no-browser-tab'
  | 'unreadable'
  | 'keychain'

/** Outcome of one saved-login import request. */
export type DesktopBrowserLoginImportResult =
  | {
    readonly status: 'imported'
    /** Browser and profile the cookies came from. */
    readonly label: string
    /** Cookies written into every open Browser session. */
    readonly imported: number
    /** Cookies the importer declined to copy faithfully. */
    readonly skipped: number
    /** Cookies the browser or the session rejected. */
    readonly failed: number
  }
  | { readonly status: 'unavailable'; readonly reason: DesktopBrowserLoginUnavailableReason }

/** Optional login-import operations implemented by a shell that can reach its Browser sessions. */
export interface DesktopBrowserLoginBridge {
  /** @returns saved login stores the shell can read on this machine. */
  loginSources(): Promise<readonly DesktopBrowserLoginSource[]>
  /** @param sourceId - one identity returned by `loginSources`. @returns the import outcome. */
  importLogins(sourceId: string): Promise<DesktopBrowserLoginImportResult>
}
