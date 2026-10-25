/** Saved-login bridge lookup for the Browser chrome. */
import type { DesktopBrowserLoginBridge } from '../../types.ts'

/** @returns the shell's saved-login operations, or `undefined` when this carrier has none. */
export function desktopLoginBridge(): DesktopBrowserLoginBridge | undefined {
  const carrier = (globalThis as typeof globalThis & {
    dshDesktop?: {
      readonly protocolVersion: number
      readonly browser?: { readonly login?: DesktopBrowserLoginBridge }
    }
  }).dshDesktop
  return carrier?.protocolVersion === 1 ? carrier.browser?.login : undefined
}
