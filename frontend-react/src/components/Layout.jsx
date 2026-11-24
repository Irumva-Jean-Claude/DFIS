import { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import { NavLink, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { useToast } from '../context/ToastContext'
import { api } from '../api'
import Modal from './Modal'
import PasswordInput from './PasswordInput'

function SvgIcon({ name, size = 18 }) {
  const icons = {
    grid: <><rect x="3" y="3" width="7" height="7" rx="1.2"/><rect x="14" y="3" width="7" height="7" rx="1.2"/><rect x="3" y="14" width="7" height="7" rx="1.2"/><rect x="14" y="14" width="7" height="7" rx="1.2"/></>,
    folder: <path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/>,
    database: <><ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v5a8 3 0 0016 0V6M4 11v5a8 3 0 0016 0v-5"/></>,
    search: <><circle cx="11" cy="11" r="7"/><line x1="17" y1="17" x2="22" y2="22"/></>,
    'file-text': <><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V7L14 2z"/><polyline points="14 2 14 8 20 8"/><line x1="9" y1="12" x2="15" y2="12"/><line x1="9" y1="16" x2="13" y2="16"/></>,
    clock: <><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></>,
    shield: <path d="M12 2l-9 4v6c0 5.5 3.8 10.74 9 12 5.2-1.26 9-6.5 9-12V6z"/>,
    file: <><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V7L14 2z"/><polyline points="14 2 14 8 20 8"/><line x1="9" y1="11" x2="15" y2="11"/><line x1="9" y1="15" x2="15" y2="15"/></>,
    'check-circle': <><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></>,
    users: <><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.74"/></>,
    settings: <><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/></>,
    help: <><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 015.83 1c0 2-3 3-3 3M12 17h.01"/></>,
    bell: <><path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 01-3.46 0"/></>,
    logout: <><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></>,
    menu: <><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></>,
    lock: <><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></>,
    key: <><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.778 7.778 5.5 5.5 0 017.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></>,
    shield2: <><path d="M12 2l-9 4v6c0 5.5 3.8 10.74 9 12 5.2-1.26 9-6.5 9-12V6z"/><path d="M9 12l2 2 4-4"/></>,
    timeline2: <><path d="M12 2v20M2 7h4M2 12h8M2 17h4"/><circle cx="12" cy="7" r="2" fill="currentColor"/><circle cx="12" cy="12" r="2" fill="currentColor"/><circle cx="12" cy="17" r="2" fill="currentColor"/></>,
    'chevron-right': <polyline points="9 18 15 12 9 6"/>,
    'alert-triangle': <><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></>,
    'check-all': <><polyline points="20 6 9 17 4 12"/><polyline points="20 6 13 17 11 15"/></>,
  }
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      {icons[name]}
    </svg>
  )
}

const NAV = [
  ['dashboard', 'Dashboard',           'grid'],
  ['cases',     'Investigation Cases',  'folder'],
  ['evidence',  'Digital Evidence',     'database'],
  ['analysis',  'File Analysis',        'search'],
  ['logs',      'Log Analysis',         'file-text'],
  ['timeline',  'Timeline Analysis',    'timeline2'],
  ['custody',   'Chain of Custody',     'shield'],
  ['reports',   'Forensic Reports',     'file'],
  ['audit',     'Audit Trail',          'check-circle'],
  ['users',     'User Management',      'users',    'users:manage'],
  ['settings',  'System Settings',      'settings', 'settings:manage'],
  ['help',      'Help & Guide',         'help'],
]

const IDLE_MS = 30 * 60 * 1000
const WARN_MS = 29 * 60 * 1000

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
        <label>Current password<PasswordInput name="current_password" autoComplete="current-password" required autoFocus /></label>
        <label>New password (minimum 10 characters, letters + digits)<PasswordInput name="new_password" autoComplete="new-password" required /></label>
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
  const navigate = useNavigate()
  const [collapsed, setCollapsed] = useState(false)

  // Search
  const [searchQ, setSearchQ] = useState('')
  const [searchRes, setSearchRes] = useState(null)
  const [searchOpen, setSearchOpen] = useState(false)
  const searchRef = useRef(null)
  const searchTimer = useRef(null)

  const doSearch = useCallback(async q => {
    if (!q.trim()) { setSearchRes(null); return }
    try {
      const [cases, evidence] = await Promise.all([
        api('/cases?q=' + encodeURIComponent(q) + '&size=4'),
        api('/evidence?q=' + encodeURIComponent(q) + '&size=4'),
      ])
      setSearchRes({ cases: cases.items || [], evidence: evidence.items || [] })
    } catch {}
  }, [])

  const handleSearchChange = e => {
    const v = e.target.value; setSearchQ(v); setSearchOpen(true)
    clearTimeout(searchTimer.current)
    searchTimer.current = setTimeout(() => doSearch(v), 280)
  }

  const handleSearchKey = e => {
    if (e.key === 'Enter' && searchQ.trim()) {
      setSearchOpen(false)
      navigate('/cases?q=' + encodeURIComponent(searchQ))
    }
    if (e.key === 'Escape') { setSearchOpen(false); setSearchQ('') }
  }

  useEffect(() => {
    const h = e => { if (searchRef.current && !searchRef.current.contains(e.target)) setSearchOpen(false) }
    document.addEventListener('mousedown', h)
    return () => document.removeEventListener('mousedown', h)
  }, [])

  // Notifications
  const [notifData, setNotifData] = useState(null)
  const [notifOpen, setNotifOpen] = useState(false)
  const notifRef = useRef(null)

  useEffect(() => {
    const fetch = () => api('/dashboard').then(setNotifData).catch(() => {})
    fetch()
    const t = setInterval(fetch, 60000)
    return () => clearInterval(t)
  }, [])

  useEffect(() => {
    const h = e => { if (notifRef.current && !notifRef.current.contains(e.target)) setNotifOpen(false) }
    document.addEventListener('mousedown', h)
    return () => document.removeEventListener('mousedown', h)
  }, [])

  const notifications = useMemo(() => {
    if (!notifData) return []
    const n = []
    if (notifData.pending_approvals > 0)
      n.push({ type: 'warn', icon: 'users', title: `${notifData.pending_approvals} user${notifData.pending_approvals > 1 ? 's' : ''} pending approval`, sub: 'Requires admin action — go to User Management', href: '/users' })
    if (notifData.cases?.overdue > 0)
      n.push({ type: 'warn', icon: 'clock', title: `${notifData.cases.overdue} case${notifData.cases.overdue > 1 ? 's' : ''} overdue (>30 days)`, sub: 'Review and update case status', href: '/cases' })
    const fails = (notifData.recent_integrity || []).filter(r => r.result === 'failed')
    if (fails.length > 0)
      n.push({ type: 'danger', icon: 'alert-triangle', title: `${fails.length} integrity check${fails.length > 1 ? 's' : ''} failed`, sub: fails.map(f => f.evidence).join(', '), href: '/evidence' })
    if (notifData.pending_custody?.length > 0)
      n.push({ type: 'info', icon: 'shield', title: `${notifData.pending_custody.length} custody transfer${notifData.pending_custody.length > 1 ? 's' : ''} pending`, sub: 'Evidence awaiting chain-of-custody sign-off', href: '/custody' })
    return n
  }, [notifData])

  const notifCount = notifications.length

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

  const initials = (myMe?.full_name || 'A').split(' ').map(w => w[0]).join('').slice(0, 2).toUpperCase()

  return (
    <div className="app">
      <aside id="sidebar" className={'sidebar' + (collapsed ? ' collapsed' : '')}>
        {/* Brand */}
        <div className="pro-brand">
          <div className="pro-brand-logo">
            <svg width="32" height="32" viewBox="0 0 32 32" fill="none">
              <path d="M16 2L3 7v9c0 7.5 5.4 14.6 13 16.5C23.6 30.6 29 23.5 29 16V7L16 2z"
                fill="rgba(59,130,246,.18)" stroke="#3b82f6" strokeWidth="1.4"/>
              <circle cx="16" cy="14" r="4.5" stroke="#3b82f6" strokeWidth="1.4" fill="none"/>
              <circle cx="16" cy="14" r="2" fill="#3b82f6"/>
              <path d="M11.5 20c1-2 2.6-3.5 4.5-3.5s3.5 1.5 4.5 3.5" stroke="#3b82f6" strokeWidth="1.2" strokeLinecap="round" fill="none" opacity="0.6"/>
            </svg>
          </div>
          <div className="label">
            <div className="pro-brand-name">DFIS</div>
            <div className="pro-brand-sub">Digital Forensic<br />Investigation System</div>
          </div>
        </div>

        {/* Navigation */}
        <nav id="nav">
          {NAV.filter(n => !n[3] || can(n[3])).map(n => (
            <NavLink key={n[0]} to={'/' + n[0]} className={({ isActive }) => isActive ? 'active' : ''}>
              <span className="ic"><SvgIcon name={n[2]} size={17} /></span>
              <span className="label">{n[1]}</span>
            </NavLink>
          ))}
        </nav>

        {/* System status */}
        <div className="sys-status">
          <div className="sys-status-row">
            <span className="sys-dot" />
            <span className="label" style={{ fontSize: 12, fontWeight: 600, color: 'var(--text)' }}>System Status</span>
          </div>
          <div className="label sys-status-sub">All Systems Online</div>
          <div className="label sys-ver">DFIS v{myMe?.version || '1.0.0'} | Secure & Trusted</div>
        </div>
      </aside>

      <div className="main">
        {/* Top bar */}
        <header className="topbar">
          <button id="toggle" className="btn ghost topbar-icon-btn" aria-label="Toggle sidebar" onClick={toggleSidebar}>
            <SvgIcon name="menu" size={19} />
          </button>

          <div className="topbar-search-wrap" ref={searchRef}>
            <div className="topbar-search">
              <SvgIcon name="search" size={14} />
              <input
                placeholder="Search cases, files, or evidence…"
                aria-label="Search"
                value={searchQ}
                onChange={handleSearchChange}
                onKeyDown={handleSearchKey}
                onFocus={() => searchQ && setSearchOpen(true)}
                autoComplete="off"
              />
              {searchQ && (
                <button className="search-clear" onClick={() => { setSearchQ(''); setSearchRes(null); setSearchOpen(false) }}>✕</button>
              )}
            </div>

            {searchOpen && searchRes && (
              <div className="search-dropdown">
                {searchRes.cases.length > 0 && (
                  <div className="search-section">
                    <div className="search-section-title">
                      <SvgIcon name="folder" size={12} /> Cases
                    </div>
                    {searchRes.cases.map(c => (
                      <div key={c.id} className="search-result" onClick={() => { navigate('/cases?q=' + encodeURIComponent(searchQ)); setSearchOpen(false) }}>
                        <div className="sr-badge sr-case">case</div>
                        <div className="sr-info">
                          <div className="sr-title">{c.ref} — {c.title}</div>
                          <div className="sr-sub">{c.status} · {c.priority}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
                {searchRes.evidence.length > 0 && (
                  <div className="search-section">
                    <div className="search-section-title">
                      <SvgIcon name="database" size={12} /> Evidence
                    </div>
                    {searchRes.evidence.map(ev => (
                      <div key={ev.id} className="search-result" onClick={() => { navigate('/evidence?q=' + encodeURIComponent(searchQ)); setSearchOpen(false) }}>
                        <div className="sr-badge sr-ev">file</div>
                        <div className="sr-info">
                          <div className="sr-title">{ev.ref} — {ev.original_filename}</div>
                          <div className="sr-sub">{ev.evidence_type}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
                {searchRes.cases.length === 0 && searchRes.evidence.length === 0 && (
                  <div className="search-empty">No results for "<strong>{searchQ}</strong>"</div>
                )}
                <div className="search-footer">
                  <span onClick={() => { navigate('/cases?q=' + encodeURIComponent(searchQ)); setSearchOpen(false) }}>
                    <SvgIcon name="folder" size={11} /> All cases →
                  </span>
                  <span onClick={() => { navigate('/evidence?q=' + encodeURIComponent(searchQ)); setSearchOpen(false) }}>
                    <SvgIcon name="database" size={11} /> All evidence →
                  </span>
                </div>
              </div>
            )}
          </div>

          <div className="spacer" />

          <div className="secure-badge">
            <SvgIcon name="shield2" size={15} />
            <span>Secure Connection</span>
          </div>

          <div className="tb-sep" />

          <div className="notif-wrap" ref={notifRef}>
            <button
              className="notif-btn"
              title="Notifications"
              onClick={() => setNotifOpen(o => !o)}
            >
              <SvgIcon name="bell" size={17} />
              {notifCount > 0 && <span className="notif-count">{notifCount}</span>}
            </button>

            {notifOpen && (
              <div className="notif-dropdown">
                <div className="notif-header">
                  <span>Notifications</span>
                  {notifCount > 0
                    ? <span className="notif-header-badge">{notifCount} alert{notifCount > 1 ? 's' : ''}</span>
                    : <span style={{ fontSize: 11, color: 'var(--green)' }}>All clear</span>
                  }
                </div>

                <div className="notif-list">
                  {notifications.length === 0 ? (
                    <div className="notif-empty">
                      <div className="notif-empty-icon">
                        <SvgIcon name="shield2" size={22} />
                      </div>
                      <div style={{ fontWeight: 700, fontSize: 13, color: 'var(--text)' }}>All systems clear</div>
                      <div style={{ fontSize: 12, color: 'var(--muted)', textAlign: 'center', lineHeight: 1.5 }}>
                        No pending approvals,<br />overdue cases, or failed checks.
                      </div>
                    </div>
                  ) : (
                    notifications.map((n, i) => (
                      <div
                        key={i}
                        className="notif-item"
                        onClick={() => { navigate(n.href); setNotifOpen(false) }}
                      >
                        <div className={`notif-item-icon notif-ic-${n.type}`}>
                          <SvgIcon name={n.icon} size={16} />
                        </div>
                        <div className="notif-item-body">
                          <div className="notif-item-title">{n.title}</div>
                          <div className="notif-item-sub">{n.sub}</div>
                        </div>
                        <SvgIcon name="chevron-right" size={13} style={{ color: 'var(--muted)', flexShrink: 0 }} />
                      </div>
                    ))
                  )}
                </div>

                <div className="notif-footer" onClick={() => setNotifOpen(false)}>
                  Close notifications
                </div>
              </div>
            )}
          </div>

          <div className="tb-sep" />

          <button className="user-pill" onClick={() => setPwOpen(true)} title="Change password">
            <div className="user-avatar">{initials}</div>
            <div className="label user-info">
              <div className="user-name">{myMe?.full_name || 'Admin'}</div>
              <div className="user-role">{myMe?.role}</div>
            </div>
            <span className="label" style={{ color: 'var(--muted)', fontSize: 11, marginLeft: 2 }}>▾</span>
          </button>

          <button className="btn ghost topbar-icon-btn"
            style={{ color: myMe?.mfa_enabled ? 'var(--green)' : 'var(--amber)', fontSize: 11, padding: '6px 8px' }}
            title={myMe?.mfa_enabled ? '2FA enabled' : '2FA disabled'}
            onClick={() => setMfaOpen(true)}>
            <SvgIcon name={myMe?.mfa_enabled ? 'lock' : 'key'} size={15} />
          </button>

          <button className="btn ghost topbar-icon-btn" style={{ color: 'var(--red)' }} title="Logout" onClick={handleLogout}>
            <SvgIcon name="logout" size={17} />
          </button>
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
