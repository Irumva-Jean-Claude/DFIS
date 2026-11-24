import { useState } from 'react'
import PasswordInput from '../components/PasswordInput'
import { api, setToken } from '../api'
import { useAuth } from '../context/AuthContext'

function NeonRingIcon() {
  return (
    <div className="neon-ring-wrap">
      <div className="neon-ring-outer">
        <div className="neon-ring-inner">
          <svg width="140" height="140" viewBox="0 0 140 140" fill="none">
            {/* Fingerprint-style concentric arcs */}
            <circle cx="70" cy="70" r="18" stroke="#22d3ee" strokeWidth="2" fill="none" opacity="0.9"/>
            <circle cx="70" cy="70" r="28" stroke="#22d3ee" strokeWidth="1.8" fill="none" opacity="0.85" strokeDasharray="6 3"/>
            <circle cx="70" cy="70" r="38" stroke="#22d3ee" strokeWidth="1.6" fill="none" opacity="0.8" strokeDasharray="10 4"/>
            <circle cx="70" cy="70" r="48" stroke="#22d3ee" strokeWidth="1.4" fill="none" opacity="0.7" strokeDasharray="14 5"/>
            <circle cx="70" cy="70" r="58" stroke="#22d3ee" strokeWidth="1.2" fill="none" opacity="0.5" strokeDasharray="18 6"/>
            {/* Shield outline in center */}
            <path d="M70 48l-14 5.5v9c0 8.3 5.6 16 14 18.5 8.4-2.5 14-10.2 14-18.5v-9L70 48z"
              stroke="#22d3ee" strokeWidth="1.5" fill="rgba(34,211,238,0.08)"/>
            {/* Lock inside shield */}
            <rect x="65" y="66" width="10" height="8" rx="1.5" fill="#22d3ee" opacity="0.9"/>
            <path d="M66.5 66v-3a3.5 3.5 0 017 0v3" stroke="#22d3ee" strokeWidth="1.5" fill="none"/>
            <circle cx="70" cy="70.5" r="1.5" fill="#07090f"/>
          </svg>
        </div>
      </div>
      {/* Circuit lines radiating out */}
      <div className="circuit-lines" />
    </div>
  )
}

function LoginForm({ onLogin }) {
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(false)

  const handleLogin = async e => {
    e.preventDefault(); setErr(''); setLoading(true)
    try {
      const r = await api('/auth/login', { method: 'POST', body: Object.fromEntries(new FormData(e.target)) })
      onLogin(r)
    } catch (x) { setErr(x.message) }
    finally { setLoading(false) }
  }

  return (
    <form onSubmit={handleLogin}>
      <div className="nf-group">
        <span className="nf-label">Username</span>
        <input className="nf-input" name="username" autoComplete="username" required autoFocus placeholder="Enter username" />
      </div>
      <div className="nf-group">
        <span className="nf-label">Password</span>
        <PasswordInput className="nf-input" name="password" autoComplete="current-password" required placeholder="Enter password" />
      </div>
      <button className="nf-btn" type="submit" disabled={loading}>
        {loading ? 'Authenticating…' : 'LOGIN'}
      </button>
      {err && <div className="nf-error">{err}</div>}
      <p className="nf-footer">Unauthorized access is prohibited and subject to prosecution.<br />All sessions are monitored and logged.</p>
    </form>
  )
}

function MfaForm({ mfaToken, onLogin }) {
  const [err, setErr] = useState('')
  const [recovery, setRecovery] = useState(false)
  const [loading, setLoading] = useState(false)

  const handleMfa = async e => {
    e.preventDefault(); setErr(''); setLoading(true)
    try {
      const path = recovery ? '/auth/mfa/verify-recovery' : '/auth/mfa/verify'
      const r = await api(path, { method: 'POST', body: { mfa_token: mfaToken, code: new FormData(e.target).get('code') } })
      onLogin(r)
    } catch (x) { setErr(x.message) }
    finally { setLoading(false) }
  }

  return (
    <>
      {/* Step progress bar */}
      <div className="mfa-steps">
        <div className="mfa-step-item done">
          <div className="mfa-step-circle">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round"><polyline points="20 6 9 17 4 12"/></svg>
          </div>
          <span className="mfa-step-label">Password</span>
        </div>
        <div className="mfa-step-line" />
        <div className="mfa-step-item active">
          <div className="mfa-step-circle">2</div>
          <span className="mfa-step-label">Verify</span>
        </div>
      </div>

      {/* Phone / authenticator graphic */}
      {!recovery && (
        <div className="mfa-graphic">
          <div className="mfa-phone">
            <svg width="58" height="58" viewBox="0 0 58 58" fill="none">
              <rect x="13" y="4" width="32" height="50" rx="5" fill="rgba(34,211,238,.08)" stroke="#22d3ee" strokeWidth="1.5"/>
              <line x1="22" y1="11" x2="36" y2="11" stroke="#22d3ee" strokeWidth="2" strokeLinecap="round"/>
              <rect x="18" y="20" width="22" height="20" rx="3" fill="rgba(34,211,238,.07)" stroke="rgba(34,211,238,.35)" strokeWidth="1"/>
              <text x="29" y="34" textAnchor="middle" fill="#22d3ee" fontSize="11" fontWeight="800" fontFamily="monospace" letterSpacing="4">••••••</text>
              <circle cx="29" cy="47" r="2.5" fill="rgba(34,211,238,.4)"/>
            </svg>
            <div className="mfa-phone-pulse" />
          </div>
          <div className="mfa-graphic-label">Open your authenticator app</div>
        </div>
      )}

      <form onSubmit={handleMfa} style={{ marginTop: recovery ? 8 : 0 }}>
        <div className="nf-group">
          <span className="nf-label">{recovery ? '🔑 Recovery Code' : '📱 6-Digit Authenticator Code'}</span>
          <input
            className={recovery ? 'nf-input' : 'nf-input nf-otp'}
            name="code"
            inputMode={recovery ? 'text' : 'numeric'}
            maxLength={recovery ? 20 : 6}
            required autoFocus
            placeholder={recovery ? 'Enter recovery code' : '0 0 0 0 0 0'}
          />
          {!recovery && <span className="nf-otp-hint">Enter the 6-digit code shown in your app</span>}
        </div>
        <button className="nf-btn" type="submit" disabled={loading}>
          {loading
            ? <span className="nf-btn-loading">◌ Verifying…</span>
            : <><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" style={{marginRight:6}}><path d="M12 2l-9 4v6c0 5.5 3.8 10.74 9 12 5.2-1.26 9-6.5 9-12V6z"/><path d="M9 12l2 2 4-4"/></svg>VERIFY IDENTITY</>
          }
        </button>
        {err && <div className="nf-error">⚠ {err}</div>}
      </form>

      <button className="nf-switch" type="button" onClick={() => setRecovery(r => !r)}>
        {recovery ? '← Back to authenticator code' : 'Lost your phone? Use recovery code'}
      </button>
    </>
  )
}

export default function Login() {
  const { login } = useAuth()
  const [mfaToken, setMfaToken] = useState(null)

  const handleResult = r => {
    if (r.mfa_required) { setMfaToken(r.mfa_token); return }
    setToken(r.access_token); login(r.me)
  }

  return (
    <div className="nlogin-bg">
      {/* Circuit board background */}
      <div className="circuit-bg" />

      {/* Top header */}
      <div className="nlogin-header">
        <svg width="28" height="28" viewBox="0 0 28 28" fill="none">
          <path d="M14 2L4 6v8c0 6 3.8 11.5 10 13.5C20.2 25.5 24 20 24 14V6L14 2z"
            fill="rgba(34,211,238,0.15)" stroke="#22d3ee" strokeWidth="1.2"/>
          <circle cx="14" cy="13" r="4" stroke="#22d3ee" strokeWidth="1.2" fill="none"/>
          <line x1="17" y1="16" x2="20" y2="19" stroke="#22d3ee" strokeWidth="1.5" strokeLinecap="round"/>
        </svg>
        <span className="nlogin-brand-name">DFIS</span>
      </div>

      <div className="nlogin-wrap">
        {/* Left — neon visual */}
        <div className="nlogin-visual">
          <NeonRingIcon />
          <h1 className="nlogin-title">DFIS</h1>
          <p className="nlogin-subtitle">Digital Forensics<br />Investigation System</p>
        </div>

        {/* Right — form */}
        <div className="nlogin-form-panel">
          <div className="nlogin-card">
            <h2 className="nlogin-card-title">
              {mfaToken
                ? <><span style={{color:'#22d3ee',marginRight:8}}>🔐</span>Two-Factor Auth</>
                : 'Welcome'}
            </h2>
            <p className="nlogin-card-sub">{mfaToken ? 'Step 2 of 2 — Identity verification required' : 'Sign in to your account'}</p>
            <div className="nf-sep" />
            {mfaToken
              ? <MfaForm mfaToken={mfaToken} onLogin={handleResult} />
              : <LoginForm onLogin={handleResult} />
            }
          </div>
          <p className="nlogin-official">OFFICIAL USE ONLY — Authorized personnel only</p>
        </div>
      </div>
    </div>
  )
}
