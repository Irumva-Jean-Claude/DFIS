import { useState, useEffect } from 'react'
import { api, fmt } from '../api'
import { useAuth } from '../context/AuthContext'
import Badge from '../components/Badge'
import Bars from '../components/Bars'
import Table from '../components/Table'

export default function Dashboard() {
  const { can } = useAuth()
  const [d, setD] = useState(null)

  useEffect(() => { api('/dashboard').then(setD) }, [])

  if (!d) return <div className="empty">Loading…</div>

  const stats = [
    ['Total Cases',    d.cases.total,          'var(--blue)'],
    ['Open',          d.cases.open,            'var(--amber)'],
    ['Active',        d.cases.active,          'var(--green)'],
    ['Closed',        d.cases.closed,          'var(--muted2)'],
    ['Evidence Items', d.evidence_total,       'var(--violet)'],
  ]

  return (
    <>
      <h1>Dashboard</h1>
      <p className="muted">Live operational overview — cases and evidence you are authorized to access.</p>

      {d.pending_approvals > 0 && (
        <div className="alert" style={{ borderColor: 'var(--amber)', background: 'var(--amber-bg)', marginBottom: 16 }}>
          ⚠ <strong>{d.pending_approvals} user account{d.pending_approvals > 1 ? 's' : ''}</strong> pending approval.{' '}
          <a href="#/users">Go to User Management →</a>
        </div>
      )}

      <div className="grid">
        {stats.map(([l, n, c]) => (
          <div key={l} className="card stat" style={{ '--stat-c': c }}>
            <div className="n">{n}</div>
            <div className="l">{l}</div>
          </div>
        ))}
        {d.cases.overdue > 0 && (
          <div className="card stat" style={{ '--stat-c': 'var(--red)', borderLeftColor: 'var(--red)' }}>
            <div className="n">{d.cases.overdue}</div>
            <div className="l">Overdue (&gt;30 days)</div>
          </div>
        )}
      </div>

      <div className="grid two">
        <div className="card"><h2>Evidence by type</h2><Bars data={d.evidence_by_type} /></div>
        <div className="card"><h2>Analysis jobs</h2><Bars data={d.analysis} empty="No analysis run yet." /></div>
      </div>

      <div className="card"><h2>Activity (last 14 days)</h2><Bars data={d.activity} /></div>

      <div className="grid two">
        <div className="card">
          <h2>Recent integrity checks</h2>
          <Table
            cols={[
              { label: 'Evidence', render: r => r.evidence },
              { label: 'Result', render: r => <Badge value={r.result} /> },
              { label: 'Time', render: r => fmt(r.at) },
            ]}
            rows={d.recent_integrity} empty="No integrity checks yet." />
        </div>
        <div className="card">
          <h2>Pending custody transfers</h2>
          <Table
            cols={[
              { label: 'Evidence', render: r => r.evidence },
              { label: 'Since', render: r => fmt(r.at) },
            ]}
            rows={d.pending_custody} empty="No pending transfers." />
        </div>
      </div>

      <div className="card">
        <h2>Recent audit events</h2>
        <Table
          cols={[
            { label: 'Time', render: r => fmt(r.ts) },
            { label: 'Actor', render: r => r.actor || '—' },
            { label: 'Action', render: r => r.action },
            { label: 'Outcome', render: r => <Badge value={r.outcome} /> },
          ]}
          rows={d.recent_audit} empty="No audit events visible." />
      </div>
    </>
  )
}
