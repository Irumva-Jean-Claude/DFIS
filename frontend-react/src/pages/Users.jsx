import { useState, useEffect } from 'react'
import PasswordInput from '../components/PasswordInput'
import { api, fmt } from '../api'
import { useAuth } from '../context/AuthContext'
import { useToast } from '../context/ToastContext'
import Badge from '../components/Badge'
import Table from '../components/Table'
import Modal from '../components/Modal'

const ROLES = ['admin', 'lead', 'analyst', 'custodian', 'reviewer']

export default function Users() {
  const { me } = useAuth()
  const toast = useToast()
  const [users, setUsers] = useState([])
  const [tab, setTab] = useState('active')
  const [creating, setCreating] = useState(false)
  const [tempPw, setTempPw] = useState(null)

  const load = () => api('/users').then(setUsers).catch(err => toast(err.message, true))
  useEffect(() => { load() }, [])

  const active  = users.filter(u => u.is_active)
  const pending = users.filter(u => !u.is_active)

  const approve = async id => {
    try { await api('/users/' + id + '/approve', { method: 'POST' }); toast('Account approved'); load() }
    catch (err) { toast(err.message, true) }
  }

  const patch = async (id, body) => {
    try { await api('/users/' + id, { method: 'PATCH', body }); load() }
    catch (err) { toast(err.message, true) }
  }

  const resetPw = async id => {
    if (!confirm('Reset this user\'s password? A temporary password will be generated.')) return
    try {
      const r = await api('/users/' + id + '/reset-password', { method: 'POST' })
      setTempPw(r.temporary_password)
    } catch (err) { toast(err.message, true) }
  }

  const create = async e => {
    e.preventDefault()
    const fd = new FormData(e.target)
    try {
      await api('/users', { method: 'POST', body: Object.fromEntries(fd) })
      toast('User created'); setCreating(false); load()
    } catch (err) { toast(err.message, true) }
  }

  const cols = [
    { label: 'Username',    render: u => u.username },
    { label: 'Full name',   render: u => u.full_name },
    { label: 'Email',       render: u => u.email || '—' },
    { label: 'Role',        render: u => (
      <select value={u.role} onChange={e => patch(u.id, { role: e.target.value })} disabled={u.id === me?.id}
        style={{ width: 'auto', padding: '4px 8px', fontSize: 12 }}>
        {ROLES.map(r => <option key={r}>{r}</option>)}
      </select>
    )},
    { label: 'MFA',    render: u => u.mfa_enabled ? <Badge value="active">✓ On</Badge> : <span className="muted">Off</span> },
    { label: 'Created', render: u => fmt(u.created_at) },
    { label: 'Actions', render: u => (
      <div className="row" style={{ gap: 6, flexWrap: 'nowrap' }}>
        {u.is_active
          ? <button className="btn sm danger" onClick={() => patch(u.id, { is_active: false })} disabled={u.id === me?.id}>Deactivate</button>
          : <button className="btn sm" style={{ color: 'var(--green)', borderColor: 'var(--green)' }} onClick={() => approve(u.id)}>Approve</button>
        }
        <button className="btn sm" onClick={() => resetPw(u.id)}>Reset pw</button>
      </div>
    )},
  ]

  return (
    <>
      <h1>User Management</h1>

      <div className="row">
        <div style={{ display: 'flex', gap: 4, background: 'var(--panel2)', padding: 4, borderRadius: 'var(--radius-sm)', border: '1px solid var(--line)' }}>
          {[['active', `Active (${active.length})`], ['pending', `Pending approval (${pending.length})`]].map(([t, l]) => (
            <button key={t} className={`btn sm ${tab === t ? 'primary' : 'ghost'}`} onClick={() => setTab(t)}>{l}</button>
          ))}
        </div>
        <span className="spacer" />
        <button className="btn primary" onClick={() => setCreating(true)}>New user</button>
      </div>

      {tab === 'pending' && pending.length === 0 && (
        <div className="card"><p className="muted" style={{ textAlign: 'center', padding: 20 }}>No accounts pending approval.</p></div>
      )}

      {tab === 'active' && (
        <div className="card">
          <Table cols={cols} rows={active} empty="No active users." />
        </div>
      )}

      {tab === 'pending' && pending.length > 0 && (
        <div className="card">
          <div className="note">These accounts were created but are waiting for administrator approval before the user can log in.</div>
          <Table cols={cols} rows={pending} empty="No pending accounts." />
        </div>
      )}

      {tempPw && (
        <Modal title="Temporary password" onClose={() => setTempPw(null)}>
          <p className="muted">Share this securely. The user must change it at next login.</p>
          <div className="note mono" style={{ fontSize: 18, letterSpacing: 3, textAlign: 'center', padding: 16 }}>{tempPw}</div>
          <button className="btn primary" style={{ width: '100%' }} onClick={() => setTempPw(null)}>Done</button>
        </Modal>
      )}

      {creating && (
        <Modal title="Create new user" onClose={() => setCreating(false)}>
          <form onSubmit={create}>
            <label>Username (letters, digits, . _ -)
              <input name="username" required minLength={3} maxLength={40} pattern="[A-Za-z0-9_.\-]+" />
            </label>
            <label>Full name<input name="full_name" required maxLength={100} /></label>
            <label>Email address<input name="email" type="email" maxLength={150} /></label>
            <label>Role
              <select name="role">{ROLES.map(r => <option key={r}>{r}</option>)}</select>
            </label>
            <label>Temporary password (min 10 characters, letters + digits)
              <PasswordInput name="password" autoComplete="new-password" required />
            </label>
            <button className="btn primary" style={{ width: '100%' }}>Create account</button>
          </form>
        </Modal>
      )}
    </>
  )
}
