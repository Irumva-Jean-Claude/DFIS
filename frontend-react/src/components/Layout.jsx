import { useState, useEffect, useRef, useCallback } from 'react'
import { NavLink } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { useToast } from '../context/ToastContext'
import { api } from '../api'
import Modal from './Modal'

const NAV = [
  ['dashboard',  'Dashboard',          '▣'],
  ['cases',      'Investigation Cases', '▤'],
  ['evidence',   'Digital Evidence',   '◉'],
  ['analysis',   'File Analysis',      '⌕'],
  ['logs',       'Log Analysis',       '≡'],
  ['timeline',   'Timeline Analysis',  '⌚'],
  ['custody',    'Chain of Custody',   '⛓'],
  ['reports',    'Forensic Reports',   '☷'],
  ['audit',      'Audit Trail',        '⚑'],
  ['users',      'User Management',    '☺', 'users:manage'],
  ['settings',   'System Settings',    '⚙', 'settings:manage'],
  ['help',       'Help & Guide',       '?'],
]

const IDLE_MS    = 30 * 60 * 1000   // 30 min total idle
const WARN_MS    = 29 * 60 * 1000   // warn after 29 min

function PwModal({ onClose, force }) {
  const toast = useToast()
  const submit = async e => {
    e.preventDefault()
    const fd = new FormData(e.target)
    try {
      await api('/auth/change-password', { method: 'POST', body: Object.fromEntries(fd) })
      toast('Password changed successfully')
      onClose()
    } catch (err) { toast(err.message, true) }
  }
  return (
    <Modal title="Change password" onClose={force ? null : onClose}>
      <form onSubmit={submit}>
        {force && <p className="error">You must change your temporary password before continuing.</p>}
        <label>Current password<input name="current_password" type="password" required autoFocus /></label>
        <label>New password (minimum 10 characters, letters + digits)<input name="new_password" type="password" required /></label>
        <button className="btn primary">Change password</button>
      </form>
    </Modal>
  )
}

function MfaModal({ onClose, refreshMe }) {
  const toast = useToast()
  const [status, setStatus] = useState(null)
  const [qr, setQr] = useState(null)

  const load = async () => {
    const s = await api('/auth/mfa/status')
    setStatus(s.mfa_enabled)
    if (!s.mfa_enabled) {
      const setup = await api('/auth/mfa/setup', { method: 'POST' })
      setQr(setup)
    }
  }
  useState(() => { load() }, [])

  const enable = async e => {
    e.preventDefault()
    const fd = new FormData(e.target)
    try {
      const r = await api('/auth/mfa/enable', { method: 'POST', body: Object.fromEntries(fd) })
      toast('Two-factor authentication enabled')
      refreshMe(); onClose()
      alert('Recovery codes (shown once):\n' + r.recovery_codes.join('\n'))
    } catch (err) { toast(err.message, true) }
  }

  const disable = async e => {
    e.preventDefault()
    const fd = new FormData(e.target)
    try {
      await api('/auth/mfa/disable', { method: 'POST', body: Object.fromEntries(fd) })
      toast('Two-factor authentication disabled')
      refreshMe(); onClose()
    } catch (err) { toast(err.message, true) }
  }

  if (status === null) return <Modal title="Two-factor authentication" onClose={onClose}><p className="muted">Loading…</p></Modal>

  if (!status) return (
    <Modal title="Enable two-factor authentication" onClose={onClose}>
      <div className="note">1. Scan the QR code with an authenticator app (Google Authenticator, Authy).<br />2. Enter the 6-digit code to activate.</div>
      {qr && <div className="note"><img alt="QR code" src={`data:image/png;base64,${qr.qr_png_base64}`} /><p className="mono">{qr.secret}</p></div>}
      <form onSubmit={enable}>
        <label>6-digit code<input name="code" required maxLength={6} inputMode="numeric" autoFocus /></label>
        <button className="btn primary">Enable 2FA</button>
      </form>
    </Modal>
  )

  return (
    <Modal title="Disable two-factor authentication" onClose={onClose}>
      <p className="error">Removing 2FA reduces your account security.</p>
      <form onSubmit={disable}>
        <label>6-digit code to confirm<input name="code" required maxLength={6} inputMode="numeric" /></label>
        <button className="btn primary">Disable 2FA</button>
      </form>
    </Modal>
  )
}

function SessionWarning({ secondsLeft, onStayLoggedIn }) {
  return (
    <Modal title="Session expiring soon" onClose={null}>
      <p>Your session will expire in <strong>{secondsLeft} seconds</strong> due to inactivity.</p>
      <p className="muted">Click the button below to stay logged in.</p>
      <button className="btn primary" onClick={onStayLoggedIn}>Stay logged in</button>
    </Modal>
  )
}

export default function Layout({ children }) {
  const { me, logout, can } = useAuth()
  const toast = useToast()
  const [collapsed, setCollapsed] = useState(false)
  const [pwOpen, setPwOpen] = useState(me?.must_change_password ?? false)
  const [mfaOpen, setMfaOpen] = useState(false)
  const [myMe, setMyMe] = useState(me)
  const [sessionWarning, setSessionWarning] = useState(false)
  const [secondsLeft, setSecondsLeft] = useState(60)

  const lastActivity = useRef(Date.now())
  const warningTimer = useRef(null)
  const countdownTimer = useRef(null)

  const refreshMe = async () => {
    try { const u = await api('/auth/me'); setMyMe(u) } catch {}
  }

  const handleLogout = async () => {
    try { await api('/auth/logout', { method: 'POST' }) } catch {}
    logout()
  }

  const resetIdle = useCallback(() => {
    lastActivity.current = Date.now()
    if (sessionWarning) {
      setSessionWarning(false)
      clearInterval(countdownTimer.current)
    }
  }, [sessionWarning])

  // Session idle timer
  useEffect(() => {
    const events = ['mousemove', 'keydown', 'click', 'touchstart', 'scroll']
    events.forEach(e => window.addEventListener(e, resetIdle, { passive: true }))

    warningTimer.current = setInterval(() => {
      const idle = Date.now() - lastActivity.current
      if (idle >= IDLE_MS) {
        clearInterval(warningTimer.current)
        clearInterval(countdownTimer.current)
        toast('Session expired due to inactivity.', true)
        handleLogout()
      } else if (idle >= WARN_MS && !sessionWarning) {
        setSessionWarning(true)
        setSecondsLeft(Math.ceil((IDLE_MS - idle) / 1000))
        countdownTimer.current = setInterval(() => {
          const remaining = Math.ceil((IDLE_MS - (Date.now() - lastActivity.current)) / 1000)
          setSecondsLeft(remaining > 0 ? remaining : 0)
        }, 1000)
      }
    }, 15000)

    return () => {
      events.forEach(e => window.removeEventListener(e, resetIdle))
      clearInterval(warningTimer.current)
      clearInterval(countdownTimer.current)
    }
  }, [])

  const toggleSidebar = () => {
    if (window.innerWidth < 800) {
      document.getElementById('sidebar').classList.toggle('open')
    } else {
      setCollapsed(c => !c)
    }
  }

  return (
    <div className="app">
      <aside id="sidebar" className={'sidebar' + (collapsed ? ' collapsed' : '')}>
        <div className="brand">
          <span className="logo" style={{ color: 'var(--blue)' }}>⚿</span>
          <span className="label">DFIS</span>
        </div>
        <nav id="nav">
          {NAV.filter(n => !n[3] || can(n[3])).map(n => (
            <NavLink key={n[0]} to={'/' + n[0]} className={({ isActive }) => isActive ? 'active' : ''}>
              <span className="ic" aria-hidden="true">{n[2]}</span>
              <span className="label">{n[1]}</span>
            </NavLink>
          ))}
        </nav>
        <div style={{ padding: '12px 20px', borderTop: '1px solid var(--line)', fontSize: 11, color: 'var(--muted)' }}>
          <span className="label">v{myMe?.version || '1.0.0'}</span>
        </div>
      </aside>

      <div className="main">
        <header className="topbar">
          <button id="toggle" className="btn ghost" aria-label="Toggle sidebar" onClick={toggleSidebar}>☰</button>
          <div className="spacer" />
          <span className="muted">{myMe?.full_name} <span style={{ color: 'var(--muted)', fontSize: 12 }}>({myMe?.role})</span></span>
          <button className="btn ghost" onClick={() => setPwOpen(true)}>Password</button>
          <button className="btn ghost" onClick={() => setMfaOpen(true)}
            style={{ color: myMe?.mfa_enabled ? 'var(--green)' : 'var(--amber)' }}>
            {myMe?.mfa_enabled ? '2FA ✓' : '2FA off'}
          </button>
          <button className="btn ghost" style={{ color: 'var(--red)' }} onClick={handleLogout}>Logout</button>
        </header>

        <div className="banner">
          OFFICIAL USE ONLY — Authorized personnel only. Unauthorized access is prohibited and subject to prosecution. All activity is logged and monitored.
        </div>

        <main tabIndex="-1">{children}</main>
      </div>

      {pwOpen && <PwModal onClose={() => setPwOpen(false)} force={myMe?.must_change_password} />}
      {mfaOpen && <MfaModal onClose={() => setMfaOpen(false)} me={myMe} refreshMe={refreshMe} />}
      {sessionWarning && (
        <SessionWarning secondsLeft={secondsLeft} onStayLoggedIn={() => { resetIdle(); refreshMe() }} />
      )}
    </div>
  )
}
