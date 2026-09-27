// ============================================================================
// ECDAT — Supabase Auth Client Module (Vercel SPA, client-side only)
// ============================================================================
// This module is used on the client side of the ECDAT Vercel SPA. It never
// touches browser-only globals at module load, so `tsc --noEmit` stays clean
// and the module is safe to import anywhere in the component tree.
//
// AUTH FLOW (client-side only, no SSR cookie dance):
//   • Sessions persist in localStorage via `persistSession: true`.
//   • `getSession()` / `getAuthenticatedUser()` read the stored session.
//   • Google OAuth (`signInWithOAuth('google')`) and Email+Password
//     (`signInWithPassword`) hand the sign-in redirect to the browser.
//   • Auth state syncs via `supabase.auth.onAuthStateChange`.
//
// RULES:
//  • NEVER expose the anon key in server-side code. The Vercel anon key is
//    stored in project env vars as `VITE_SUPABASE_ANON_KEY`.
//  • No real keys in this repo. `cp .env.example .env` is for local dev;
//    Vercel project settings hold the real keys.
//  • `verbatimModuleSyntax` is enabled — type-only imports use `import type`.
// ============================================================================

import type { Session, User, SupabaseClient } from '@supabase/supabase-js'
import { createBrowserClient } from '@supabase/ssr'

// ---------------------------------------------------------------------------
// Types (relaxed: the repo has no strict DB schema yet)
// ---------------------------------------------------------------------------
export type EcdatDatabase = Record<string, unknown>

// ---------------------------------------------------------------------------
// Browser (client-side) client
// ---------------------------------------------------------------------------
export function createClient(): SupabaseClient<EcdatDatabase> {
  const supabaseUrl =
    (import.meta.env.VITE_SUPABASE_URL as string | undefined) ?? ''
  const supabaseAnonKey =
    (import.meta.env.VITE_SUPABASE_ANON_KEY as string | undefined) ?? ''

  if (!supabaseUrl || !supabaseAnonKey) {
    console.warn(
      '[Supabase] VITE_SUPABASE_URL / VITE_SUPABASE_ANON_KEY are not set. ' +
        'Supabase auth will fail until configured in .env or Vercel env.'
    )
  }

  return createBrowserClient<EcdatDatabase>(supabaseUrl, supabaseAnonKey, {
    auth: {
      persistSession: true,
      autoRefreshToken: true,
    },
  })
}

// ---------------------------------------------------------------------------
// Session helpers
// ---------------------------------------------------------------------------
export async function getSession(): Promise<Session | null> {
  const supabase = createClient()
  const { data } = await supabase.auth.getSession()
  return data.session ?? null
}

export async function getAuthenticatedUser(): Promise<User | null> {
  const session = await getSession()
  return session?.user ?? null
}

// ---------------------------------------------------------------------------
// Auth actions
// ---------------------------------------------------------------------------
export type OAuthProvider = 'google' | 'github'

export async function signInWithOAuth(
  provider: OAuthProvider,
  redirectTo?: string
): Promise<{ success: boolean; error?: string }> {
  const supabase = createClient()
  try {
    const callbackUrl = redirectTo || windowLocation()
    const { error } = await supabase.auth.signInWithOAuth({
      provider,
      options: {
        redirectTo: callbackUrl,
        queryParams: provider === 'google' ? {
          access_type: 'offline',
          prompt: 'consent',
        } : undefined,
      },
    })
    if (error) {
      console.error('[Supabase] OAuth sign-in error:', error)
      return { success: false, error: error.message }
    }
    return { success: true }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    console.error('[Supabase] Unexpected sign-in error:', err)
    return { success: false, error: message }
  }
}

export async function signInWithEmail(
  email: string,
  password: string
): Promise<{ success: boolean; error?: string }> {
  const supabase = createClient()
  try {
    const { error } = await supabase.auth.signInWithPassword({ email, password })
    if (error) {
      console.error('[Supabase] Email sign-in error:', error)
      return { success: false, error: error.message }
    }
    return { success: true }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    console.error('[Supabase] Unexpected email sign-in error:', err)
    return { success: false, error: message }
  }
}

export async function signUpWithEmail(
  email: string,
  password: string
): Promise<{ success: boolean; error?: string }> {
  const supabase = createClient()
  try {
    const { error } = await supabase.auth.signUp({
      email,
      password,
      options: { emailRedirectTo: windowLocation() },
    })
    if (error) {
      console.error('[Supabase] Sign-up error:', error)
      return { success: false, error: error.message }
    }
    return { success: true }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    console.error('[Supabase] Unexpected sign-up error:', err)
    return { success: false, error: message }
  }
}

export async function signOut(): Promise<{ success: boolean }> {
  const supabase = createClient()
  try {
    const { error } = await supabase.auth.signOut()
    if (error) {
      console.error('[Supabase] Sign-out error:', error)
      return { success: false }
    }
    return { success: true }
  } catch (err) {
    console.error('[Supabase] Unexpected sign-out error:', err)
    return { success: false }
  }
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------
function windowLocation(): string {
  const customRedirect = import.meta.env.VITE_AUTH_REDIRECT_URL as string | undefined
  if (customRedirect && customRedirect.trim()) {
    return customRedirect.trim()
  }
  if (typeof window === 'undefined') return `${globalThis.location?.origin || ''}/`
  return `${window.location.origin}/`
}

export function buildRedirectUrl(
  baseUrl: string,
  callback: string = '/'
): string {
  try {
    const parsed = new URL(baseUrl)
    parsed.pathname = callback
    return parsed.toString()
  } catch {
    return `${baseUrl.replace(/\/$/, '')}${callback}`
  }
}
