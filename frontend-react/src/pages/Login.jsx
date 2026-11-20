import { useState } from 'react'
import { api, setToken } from '../api'
import { useAuth } from '../context/AuthContext'

export default function Login() {
  const { login } = useAuth()
  const [err, setErr] = useState('')
  const [mfaToken, setMfaToken] = useState(null)
  const [mfaErr, setMfaErr] = useState('')
  const [recovery, setRecovery] = useState(false)

  const handleLogin = async e => {
    e.preventDefault()
    setErr('')
    const fd = new FormData(e.target)
    try {
      const r = await api('/auth/login', { method: 'POST', body: Object.fromEntries(fd) })
      if (r.mfa_required) { setMfaToken(r.mfa_token); e.target.reset(); return }
      setToken(r.access_token)
      login(r.me)
    } catch (x) { setErr(x.message) }
  }

  const handleMfa = async e => {
    e.preventDefault()
    setMfaErr('')
    const fd = new FormData(e.target)
    try {
      const path = recovery ? '/auth/mfa/verify-recovery' : '/auth/mfa/verify'
      const r = await api(path, { method: 'POST', body: { mfa_token: mfaToken, code: fd.get('code') } })
      setToken(r.access_token)
      login(r.me)
    } catch (x) { setMfaErr(x.message) }
  }

  if (mfaToken) return (
    <div className="login">
      <form className="card login-card" onSubmit={handleMfa}>
        <div className="brand big">
          <span className="logo" style={{ color: 'var(--blue)' }}>⚿</span>
          <span> DFIS</span>
        </div>
        <p className="muted" style={{ textAlign: 'center', marginBottom: 24 }}>
          Two-factor authentication required.<br />
          <small>{recovery ? 'Enter your recovery code.' : 'Enter the 6-digit code from your authenticator app.'}</small>
        </p>
        <label>{recovery ? 'Recovery code' : 'Authenticator code'}
          <input name="code" inputMode={recovery ? 'text' : 'numeric'} autoComplete="one-time-code"
            maxLength={recovery ? 20 : 6} required autoFocus />
        </label>
        <div className="row">
          <button className="btn primary" type="submit">Verify</button>
          <button className="btn ghost" type="button" onClick={() => setRecovery(r => !r)}>
            {recovery ? 'Use authenticator code' : 'Use recovery code'}
          </button>
        </div>
        {mfaErr && <p className="error">{mfaErr}</p>}
      </form>
    </div>
  )

  return (
    <div className="login">
      <form className="card login-card" onSubmit={handleLogin}>
        <div className="brand big">
          <span className="logo" style={{ color: 'var(--blue)' }}>⚿</span>
          <span> DFIS</span>
        </div>
        <p className="muted" style={{ textAlign: 'center', marginBottom: 28 }}>
          Digital Forensics Investigation System<br />
          <small style={{ color: 'var(--muted)' }}>Authorized personnel only</small>
        </p>
        <label>Username<input name="username" autoComplete="username" required autoFocus /></label>
        <label>Password<input name="password" type="password" autoComplete="current-password" required /></label>
        <button className="btn primary" type="submit" style={{ width: '100%', padding: '11px' }}>Sign in</button>
        {err && <p className="error" style={{ marginTop: 10 }}>{err}</p>}
        <p style={{ textAlign: 'center', marginTop: 20, fontSize: 11, color: 'var(--muted)', lineHeight: 1.6 }}>
          Unauthorized access is prohibited.<br />All sessions are monitored and logged.
        </p>
      </form>
    </div>
  )
}
