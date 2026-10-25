/**
 * Platform WebAuthn configuration for the Desktop shell.
 *
 * Electron only services platform-authenticator WebAuthn requests after
 * `app.configureWebAuthn`, and macOS stores those credentials under the
 * keychain access group named here. The same group must be present in the
 * signed application's `keychain-access-groups` entitlement
 * (`scripts/macos-entitlements.plist`); an unsigned or differently signed
 * build makes the call fail and the Browser tab keeps password-only sign-in.
 */

import { app } from 'electron'

/**
 * Keychain access group that stores Desktop Touch ID credentials.
 * Keep this value in sync with `scripts/macos-entitlements.plist`.
 */
export const WEBAUTHN_KEYCHAIN_ACCESS_GROUP = 'NAN929V4UM.com.deepseek.dsh.webauthn'

/**
 * Enable the macOS Touch ID platform authenticator for every embedded Browser session.
 * Must run after the application is ready and before the first webview is attached.
 */
export function configurePlatformWebAuthn(): void {
  if (process.platform !== 'darwin') return
  try {
    app.configureWebAuthn({
      touchID: {
        keychainAccessGroup: WEBAUTHN_KEYCHAIN_ACCESS_GROUP,
        promptReason: 'sign in to $1',
      },
    })
  } catch (error) {
    // Unsigned development builds and stripped entitlements cannot store credentials.
    console.warn('dsh desktop: Touch ID WebAuthn is unavailable', error)
  }
}
