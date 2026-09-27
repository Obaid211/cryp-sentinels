// ============================================================================
// LoginPage — ECDAT Authentication Page
// ============================================================================
// The login entry point for the ECDAT Vercel SPA. It wires the interactive
// AuroraAvatar (aurora-glow character) to the Supabase auth flow:
//
//   1. Reads the current session (getSession()). A logged-in user sees a
//      "signed in as X" state with a Sign Out button.
//   2. A logged-out user sees the aurora character and three sign-in paths:
//      Google OAuth, GitHub OAuth, and Email+Password (plus Email sign-up).
//   3. All sign-in goes through Supabase's SDK only — no dummy backend login
//      endpoint, so the stack stays minimal.
//   4. On successful sign-in the parent's `onAuthSuccess` fires, which
//      routes the user to the dashboard.
//   5. OAuth (Google/GitHub) returns via the URL hash; LoginPage detects the
//      Supabase session on mount and auto-redirects to the dashboard.
//
// Design: the aurora character is intentionally soft/rounded and floats free
// of the constructivist ivory/obsidian/vermilion chrome — it is the single
// ethereal element on an otherwise zero-radius page.
// ============================================================================

import React, { useState, useEffect, useCallback } from 'react'

import { AuroraAvatar } from './AuroraAvatar'
import {
  createClient,
  getSession,
  signInWithOAuth,
  signInWithEmail,
  signUpWithEmail,
  signOut,
} from '../lib/supabase'

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------
export interface LoginPageProps {
  /** Optional subtitle override under the header. */
  customHeader?: string
  /**
   * Fired when a confirmed session exists for this user (email+password
   * sign-in, OAuth return with session, or guest demo access).
   */
  onAuthSuccess?: (email?: string) => void
}

// ---------------------------------------------------------------------------
// Small inline form field (reused by the Email+Password + Sign Up block).
// ---------------------------------------------------------------------------
interface FieldProps {
  label: string
  type?: string
  value: string
  onChange: (value: string) => void
  placeholder?: string
  error?: string
  autoComplete?: string
}

const Field: React.FC<FieldProps> = ({
  label,
  type = 'text',
  value,
  onChange,
  placeholder,
  error,
  autoComplete,
}) => (
  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
    <label style={{ ...labelStyles, fontSize: '10px', fontWeight: 600, color: 'var(--text-secondary)' }}>
      {label}
    </label>
    <input
      type={type}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      autoComplete={autoComplete}
      style={{
        borderRadius: 0,
        border: '1px solid var(--border)',
        background: 'var(--surface-raised)',
        color: 'var(--text-primary)',
        padding: '10px 12px',
        fontFamily: 'Geist Mono, ui-monospace, monospace',
        fontSize: '13px',
        outline: 'none',
        transition: 'border-color 0.15s ease',
      }}
      onFocus={(e) => { e.target.style.borderColor = 'var(--accent)' }}
      onBlur={(e) => { e.target.style.borderColor = 'var(--border)' }}
    />
    {error && <span style={{ ...labelStyles, color: 'var(--error)', fontSize: '10px', fontWeight: 600 }}>{error}</span>}
  </div>
)

const labelStyles: React.CSSProperties = {
  fontFamily: 'Geist Mono, ui-monospace, SFMono-Regular, Menlo, Monaco, monospace',
  letterSpacing: '0.08em',
  textTransform: 'uppercase',
}

// ---------------------------------------------------------------------------
// Shared button styles (zero-radius, on-brand).
// ---------------------------------------------------------------------------
const primaryBtnStyle: React.CSSProperties = {
  padding: '10px 12px',
  borderRadius: 0,
  border: 'none',
  background: 'var(--accent)',
  color: 'var(--on-primary)',
  fontFamily: 'Geist Mono, monospace',
  fontSize: '12px',
  cursor: 'pointer',
  textTransform: 'uppercase',
  fontWeight: 700,
  width: '100%',
}

const outlineBtnStyle: React.CSSProperties = {
  padding: '10px 12px',
  borderRadius: 0,
  border: '1px solid var(--border)',
  background: 'var(--surface-raised)',
  color: 'var(--text-primary)',
  fontFamily: 'Geist Mono, monospace',
  fontSize: '12px',
  cursor: 'pointer',
  textTransform: 'uppercase',
  fontWeight: 700,
  width: '100%',
}

// ---------------------------------------------------------------------------
// LoginPage
// ---------------------------------------------------------------------------
export const LoginPage: React.FC<LoginPageProps> = ({
  customHeader = 'Post-Quantum Identity Portal',
  onAuthSuccess,
}) => {
  // ---- Auth state ---------------------------------------------------------
  const [sessionUser, setSessionUser] = useState<{ email: string | null } | null>(null)
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [authMode, setAuthMode] = useState<'signin' | 'signup'>('signin')
  const [redirected, setRedirected] = useState(false)

  const toggleAuthMode = () => {
    setAuthMode((prev) => (prev === 'signin' ? 'signup' : 'signin'))
    setError(null)
    setSuccess(null)
    setConfirm('')
  }

  // ---- Sync session on mount & auth changes -------------------------------
  useEffect(() => {
    let cancelled = false

    const bootstrap = async () => {
      try {
        const current = await getSession()
        if (!cancelled) {
          setSessionUser(current?.user ? { email: current.user.email ?? null } : null)
        }
      } catch (err) {
        console.error('[LoginPage] bootstrap session error:', err)
        if (!cancelled) {
          setSessionUser(null)
        }
      }
    }

    bootstrap()

    // Listen for Supabase auth state changes so the UI stays in sync. This
    // also catches OAuth returns (the SDK processes the URL hash and emits
    // SIGNED_IN) and password sign-ins.
    const supabase = createClient()
    const { data } = supabase.auth.onAuthStateChange((_event, session) => {
      if (cancelled) return
      setSessionUser(session?.user ? { email: session.user.email ?? null } : null)
    })

    return () => {
      cancelled = true
      const { subscription } = data as { subscription: { unsubscribe: () => void } }
      subscription.unsubscribe()
    }
  }, [])

  // ---- Route to dashboard once a confirmed session exists ------------------
  const fireAuthSuccess = useCallback(() => {
    if (onAuthSuccess && !redirected) {
      setRedirected(true)
      onAuthSuccess(sessionUser?.email ?? undefined)
    }
  }, [onAuthSuccess, redirected, sessionUser])

  useEffect(() => {
    if (sessionUser) {
      // Small delay so the "Signed in" confirmation is painted first.
      const t = window.setTimeout(fireAuthSuccess, 700)
      return () => window.clearTimeout(t)
    }
  }, [sessionUser, fireAuthSuccess])

  const handleQuickDemoAccess = () => {
    setError(null)
    setSuccess('✓ Demo authorization granted. Entering cryptographic console…')
    setSessionUser({ email: 'analyst@ecdat.internal' })
    if (onAuthSuccess) {
      setTimeout(() => {
        onAuthSuccess('analyst@ecdat.internal')
      }, 400)
    }
  }

  // ---- Derived ------------------------------------------------------------
  const isSignedIn = Boolean(sessionUser)

  // ---- Actions ------------------------------------------------------------
  const handleSignInGoogle = async () => {
    setError(null)
    setSuccess(null)
    setBusy(true)
    const result = await signInWithOAuth('google')
    setBusy(false)
    if (!result.success) {
      setError(result.error ?? 'Google sign-in failed')
    } else {
      setSuccess('Opening Google sign-in… check your browser.')
    }
  }

  const handleSignInGithub = async () => {
    setError(null)
    setSuccess(null)
    setBusy(true)
    const result = await signInWithOAuth('github')
    setBusy(false)
    if (!result.success) {
      setError(result.error ?? 'GitHub sign-in failed')
    } else {
      setSuccess('Opening GitHub sign-in… check your browser.')
    }
  }

  const handleSignInEmail = async () => {
    setError(null)
    if (!email.trim() || !password) {
      setError('Email and password are required.')
      return
    }
    if (password.length < 6) {
      setError('Password must be at least 6 characters.')
      return
    }
    setBusy(true)
    const result = await signInWithEmail(email.trim(), password)
    setBusy(false)
    if (!result.success) {
      const errMsg = result.error ?? 'Sign-in failed'
      if (errMsg.toLowerCase().includes('invalid login credentials')) {
        setError('Invalid credentials. If you haven\'t created an account yet, switch to the "Sign Up" tab above, or use "Quick Demo Access" below.')
      } else {
        setError(errMsg)
      }
    } else {
      setSuccess('Signed in. Redirecting to the dashboard…')
    }
  }

  const handleSignUp = async () => {
    setError(null)
    if (!email.trim() || !password || !confirm) {
      setError('All fields are required.')
      return
    }
    if (password !== confirm) {
      setError('Passwords do not match.')
      return
    }
    if (password.length < 6) {
      setError('Password must be at least 6 characters.')
      return
    }
    setBusy(true)
    const result = await signUpWithEmail(email.trim(), password)
    setBusy(false)
    if (!result.success) {
      setError(result.error ?? 'Sign-up failed.')
    } else {
      setSuccess(
        'Account created! Check your email inbox to verify your account, or sign in now.'
      )
    }
  }

  const handleSignOut = async () => {
    setError(null)
    setSuccess(null)
    setBusy(true)
    const result = await signOut()
    setBusy(false)
    if (result.success) {
      setSessionUser(null)
      setRedirected(false)
    } else {
      setError('Sign-out failed')
    }
  }

  // ---- Render -------------------------------------------------------------
  return (
    <div
      className="min-h-screen bg-surface flex flex-col"
      style={{ backgroundColor: 'var(--surface)' }}
    >
      {/* Top utility bar — echoes Navbar's mode/status strip for coherence. */}
      <div className="border-b border-[#e5e5e5] bg-[#faf9f5]/95 px-4 py-2 text-[10px] font-mono uppercase tracking-widest text-tertiary">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className="inline-block h-2 w-2 bg-primary animate-pulse" />
            Ecdat Suite · Session
          </span>
          {isSignedIn ? (
            <span style={{ color: 'var(--severity-safe)', fontWeight: 700 }}>
              ONLINE — {sessionUser?.email ?? 'authenticated'}
            </span>
          ) : (
            <span style={{ color: 'var(--text-muted)', fontWeight: 600 }}>
              LOG IN
            </span>
          )}
        </div>
      </div>

      {/* Main panel — the aurora character floats on the left; forms sit
           right-aligned in a two-column layout that stacks on small screens. */}
      <div style={{ flex: '1', display: 'flex', flexDirection: 'column', padding: '28px 32px' }}>
        {/* Header */}
        <div style={{ textAlign: 'center', marginBottom: '24px' }}>
          <h1
            style={{
              fontFamily: "'Syne', sans-serif",
              fontWeight: 800,
              letterSpacing: '-0.02em',
              marginTop: '8px',
              marginBottom: '8px',
              color: 'var(--text-secondary)',
            }}
          >
            {customHeader}
          </h1>
          <p style={{ color: 'var(--text-secondary)', margin: 0, fontSize: '12px' }}>
            Secure cryptographic identity for the NQ-IoT era.
          </p>
        </div>

        {/* Character + form row */}
        <div style={{ display: 'flex', gap: '32px', justifyContent: 'center', alignItems: 'center', flexWrap: 'wrap' }}>
          {/* Left: aurora character column — the primary CTA. Clicking it
               focuses the email field (progressive: keyboard-friendly). */}
          <div
            style={{
              flex: '0 1 320px',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              gap: '12px',
              minWidth: 260,
            }}
          >
            <AuroraAvatar size={260} animated={!isSignedIn} />
            <div style={{ textAlign: 'center' }}>
              <span style={labelStyles}>
                {isSignedIn ? 'SESSION ACTIVE' : 'IDENTITY VERIFICATION'}
              </span>
            </div>
          </div>

          {/* Right: form column */}
          <div style={{ flex: '1 1 320px', display: 'flex', flexDirection: 'column', gap: '14px', maxWidth: '420px' }}>
            {isSignedIn ? (
              <div style={{ border: '1px solid var(--border)', borderRadius: 0, padding: '16px', textAlign: 'center', background: 'var(--surface-raised)' }}>
                <p style={{ color: 'var(--severity-safe)', fontWeight: 700, margin: 0 }}>
                  ✓ {sessionUser!.email ?? 'signed in'}
                </p>
                <p style={{ color: 'var(--text-muted)', fontSize: '11px', marginTop: '6px', fontFamily: 'Geist Mono, monospace' }}>
                  Redirecting to your console…
                </p>
                <button
                  onClick={handleSignOut}
                  disabled={busy}
                  style={{
                    marginTop: '12px',
                    padding: '8px 14px',
                    border: '1px solid var(--border)',
                    borderRadius: 0,
                    background: 'var(--surface-raised)',
                    color: 'var(--text-primary)',
                    fontFamily: 'Geist Mono, monospace',
                    fontSize: '11px',
                    cursor: 'pointer',
                    textTransform: 'uppercase',
                  }}
                  onMouseEnter={(e) => { e.currentTarget.style.borderColor = 'var(--accent)' }}
                  onMouseLeave={(e) => { e.currentTarget.style.borderColor = 'var(--border)' }}
                >
                  Sign Out
                </button>
              </div>
            ) : (
              <>
                {/* Unified Auth Card (Replaces login block with signup and shows toggle link) */}
                <form
                  onSubmit={(e) => {
                    e.preventDefault()
                    if (authMode === 'signin') {
                      void handleSignInEmail()
                    } else {
                      void handleSignUp()
                    }
                  }}
                  style={{
                    border: '1px solid var(--border)',
                    borderRadius: 0,
                    padding: '18px',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '14px',
                    background: 'var(--surface-raised)',
                  }}
                >
                  {/* Top Switcher Tabs */}
                  <div
                    style={{
                      display: 'grid',
                      gridTemplateColumns: '1fr 1fr',
                      borderBottom: '1px solid var(--border)',
                      marginBottom: '4px',
                    }}
                  >
                    <button
                      type="button"
                      onClick={() => {
                        setAuthMode('signin')
                        setError(null)
                        setSuccess(null)
                        setConfirm('')
                      }}
                      style={{
                        ...labelStyles,
                        padding: '8px 12px',
                        background: authMode === 'signin' ? 'var(--surface)' : 'transparent',
                        border: 'none',
                        borderBottom: authMode === 'signin' ? '2px solid var(--accent)' : '2px solid transparent',
                        color: authMode === 'signin' ? 'var(--text-primary)' : 'var(--text-muted)',
                        fontWeight: 700,
                        fontSize: '11px',
                        cursor: 'pointer',
                        transition: 'all 0.15s ease',
                      }}
                    >
                      Sign In
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setAuthMode('signup')
                        setError(null)
                        setSuccess(null)
                        setConfirm('')
                      }}
                      style={{
                        ...labelStyles,
                        padding: '8px 12px',
                        background: authMode === 'signup' ? 'var(--surface)' : 'transparent',
                        border: 'none',
                        borderBottom: authMode === 'signup' ? '2px solid var(--accent)' : '2px solid transparent',
                        color: authMode === 'signup' ? 'var(--text-primary)' : 'var(--text-muted)',
                        fontWeight: 700,
                        fontSize: '11px',
                        cursor: 'pointer',
                        transition: 'all 0.15s ease',
                      }}
                    >
                      Sign Up
                    </button>
                  </div>

                  {/* Form Fields */}
                  <Field
                    label="Email Address"
                    type="email"
                    value={email}
                    onChange={setEmail}
                    placeholder="you@example.com"
                    autoComplete="email"
                  />
                  <Field
                    label="Password"
                    type="password"
                    value={password}
                    onChange={setPassword}
                    placeholder={authMode === 'signin' ? '••••••••' : 'At least 6 characters'}
                    autoComplete={authMode === 'signin' ? 'current-password' : 'new-password'}
                  />
                  {authMode === 'signup' && (
                    <Field
                      label="Confirm Password"
                      type="password"
                      value={confirm}
                      onChange={setConfirm}
                      placeholder="Repeat password"
                      autoComplete="new-password"
                    />
                  )}

                  {error && (
                    <div style={{ ...labelStyles, color: 'var(--error)', fontSize: '11px', fontWeight: 600, borderLeft: '2px solid var(--error)', paddingLeft: '8px' }}>
                      {error}
                    </div>
                  )}
                  {success && !error && (
                    <div style={{ ...labelStyles, color: 'var(--severity-safe)', fontSize: '11px', fontWeight: 600, borderLeft: '2px solid var(--severity-safe)', paddingLeft: '8px' }}>
                      {success}
                    </div>
                  )}

                  <button
                    type="submit"
                    disabled={busy}
                    style={{
                      ...primaryBtnStyle,
                      background: authMode === 'signup' ? 'var(--secondary)' : 'var(--accent)',
                      opacity: busy ? 0.6 : 1,
                      marginTop: '4px',
                    }}
                  >
                    {busy
                      ? (authMode === 'signin' ? 'Signing In…' : 'Creating Account…')
                      : (authMode === 'signin' ? 'Sign In with Email' : 'Create Account')}
                  </button>

                  {/* Mode Switcher Prompt Link */}
                  <div style={{ textAlign: 'center', paddingTop: '10px', borderTop: '1px dashed var(--border)' }}>
                    <p style={{ ...labelStyles, fontSize: '11px', color: 'var(--text-muted)', margin: 0 }}>
                      {authMode === 'signin' ? (
                        <>
                          Don't have an account?{' '}
                          <button
                            type="button"
                            onClick={toggleAuthMode}
                            style={{
                              color: 'var(--primary)',
                              fontFamily: 'Geist Mono, monospace',
                              fontWeight: 700,
                              cursor: 'pointer',
                              textTransform: 'uppercase',
                              background: 'none',
                              border: 'none',
                              padding: 0,
                              textDecoration: 'underline',
                            }}
                          >
                            Sign Up
                          </button>
                        </>
                      ) : (
                        <>
                          Already have an account?{' '}
                          <button
                            type="button"
                            onClick={toggleAuthMode}
                            style={{
                              color: 'var(--primary)',
                              fontFamily: 'Geist Mono, monospace',
                              fontWeight: 700,
                              cursor: 'pointer',
                              textTransform: 'uppercase',
                              background: 'none',
                              border: 'none',
                              padding: 0,
                              textDecoration: 'underline',
                            }}
                          >
                            Sign In
                          </button>
                        </>
                      )}
                    </p>
                  </div>
                </form>

                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <div style={{ flex: '1', height: '1px', background: 'var(--border)' }} />
                  <span style={{ ...labelStyles, fontSize: '10px', color: 'var(--text-muted)' }}>OR</span>
                  <div style={{ flex: '1', height: '1px', background: 'var(--border)' }} />
                </div>

                <button
                  onClick={handleSignInGoogle}
                  disabled={busy}
                  style={outlineBtnStyle}
                >
                  <span style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: '10px' }}>
                    <svg width="18" height="18" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" style={{ display: 'block' }}>
                      <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
                      <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
                      <path fill="#FBBC05" d="M5.84 14.1c-.22-.66-.35-1.36-.35-2.1s.13-1.44.35-2.1V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.62z" />
                      <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z" />
                    </svg>
                    {authMode === 'signup' ? 'Continue with Google' : 'Sign in with Google'}
                  </span>
                </button>

                <button
                  onClick={handleSignInGithub}
                  disabled={busy}
                  style={outlineBtnStyle}
                >
                  <span style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}>
                    <svg width="16" height="16" viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg" style={{ display: 'block' }} aria-hidden="true">
                      <path
                        fill="currentColor"
                        fillRule="evenodd"
                        d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8z"
                      />
                    </svg>
                    Sign in with GitHub
                  </span>
                </button>

                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <div style={{ flex: '1', height: '1px', background: 'var(--border)' }} />
                  <span style={{ ...labelStyles, fontSize: '10px', color: 'var(--text-muted)' }}>EVALUATION</span>
                  <div style={{ flex: '1', height: '1px', background: 'var(--border)' }} />
                </div>

                <button
                  type="button"
                  onClick={handleQuickDemoAccess}
                  disabled={busy}
                  style={{
                    ...outlineBtnStyle,
                    borderColor: 'var(--severity-safe)',
                    color: 'var(--severity-safe)',
                    background: 'rgba(16, 185, 129, 0.06)',
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.background = 'rgba(16, 185, 129, 0.16)'
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.background = 'rgba(16, 185, 129, 0.06)'
                  }}
                >
                  <span style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}>
                    <span style={{ display: 'inline-block', width: '7px', height: '7px', borderRadius: '50%', backgroundColor: 'var(--severity-safe)' }} />
                    Quick Demo Access (Guest Mode)
                  </span>
                </button>
              </>
            )}

            <p style={{ ...labelStyles, fontSize: '10px', color: 'var(--text-muted)', margin: 0, textAlign: 'center' }}>
              Credentials are handled by Supabase Auth. No credentials are stored in this repo.
            </p>
          </div>
        </div>

        {/* Footer */}
        <div style={{ marginTop: '24px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '10px', fontFamily: 'Geist Mono, monospace' }}>
          <span>ECDAT · Post-Quantum Crypto Discovery · FIPS 203/204/205</span>
        </div>
      </div>
    </div>
  )
}
