import { useState, useEffect } from 'react'
import { api, fmt } from '../api'
import { useAuth } from '../context/AuthContext'
import Badge from '../components/Badge'
import Table from '../components/Table'

const TYPE_COLORS = {
  document: '#3b82f6', image: '#10b981', disk_image: '#f59e0b',
  memory_dump: '#ef4444', network_capture: '#8b5cf6',
  log_file: '#06b6d4', archive: '#f97316', other: '#6b7280',
  text: '#a78bfa', binary: '#f43f5e',
}

function DonutChart({ data }) {
  const total = data.reduce((s, d) => s + (d.value || 0), 0)
  if (!total) return <p className="muted" style={{ padding: '20px 0' }}>No evidence yet.</p>

  let deg = 0
  const gradient = data.filter(d => d.value > 0).map(d => {
    const pct = (d.value / total) * 360
    const color = TYPE_COLORS[d.label] || '#6b7280'
    const seg = `${color} ${deg.toFixed(1)}deg ${(deg + pct).toFixed(1)}deg`
    deg += pct
    return seg
  }).join(', ')

  return (
    <div className="donut-wrap">
      <div className="donut" style={{ background: `conic-gradient(${gradient})` }}>
        <div className="donut-hole">
          <div className="donut-num">{total}</div>
          <div className="donut-unit">Items</div>
        </div>
      </div>
      <div className="donut-legend">
        {data.filter(d => d.value > 0).map(d => (
          <div key={d.label} className="donut-item">
            <span className="donut-dot" style={{ background: TYPE_COLORS[d.label] || '#6b7280' }} />
            <span className="donut-lbl2">{d.label}</span>
            <span className="donut-val">{d.value}</span>
            <span className="donut-pct">({((d.value / total) * 100).toFixed(1)}%)</span>
          </div>
        ))}
      </div>
    </div>
  )
}

function ActivityChart({ data }) {
  if (!data?.length) return <p className="muted" style={{ padding: '20px 0' }}>No activity data.</p>
  const W = 480, H = 150
  const PAD = { t: 16, r: 16, b: 36, l: 32 }
  const iW = W - PAD.l - PAD.r
  const iH = H - PAD.t - PAD.b
  const max = Math.max(...data.map(d => d.value), 1)
  const xs = data.map((_, i) => PAD.l + (i / Math.max(data.length - 1, 1)) * iW)
  const ys = data.map(d => PAD.t + iH - (d.value / max) * iH)
  const linePath = xs.map((x, i) => `${i === 0 ? 'M' : 'L'}${x.toFixed(1)},${ys[i].toFixed(1)}`).join(' ')
  const areaPath = linePath + ` L${xs[xs.length - 1].toFixed(1)},${PAD.t + iH} L${PAD.l},${PAD.t + iH} Z`
  const step = Math.ceil(data.length / 7)
  const yTicks = [0, Math.round(max / 2), max]
  return (
    <svg viewBox={`0 0 ${W} ${H}`} style={{ width: '100%', height: 'auto' }}>
      <defs>
        <linearGradient id="actGrad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#22d3ee" stopOpacity="0.28" />
          <stop offset="100%" stopColor="#22d3ee" stopOpacity="0" />
        </linearGradient>
      </defs>
      {yTicks.map(v => (
        <g key={v}>
          <line x1={PAD.l} y1={PAD.t + iH - (v / max) * iH} x2={W - PAD.r} y2={PAD.t + iH - (v / max) * iH}
            stroke="rgba(255,255,255,0.05)" strokeWidth="1" />
          <text x={PAD.l - 5} y={PAD.t + iH - (v / max) * iH + 4} textAnchor="end" fill="#6b7280" fontSize="10">{v}</text>
        </g>
      ))}
      <path d={areaPath} fill="url(#actGrad)" />
      <path d={linePath} fill="none" stroke="#22d3ee" strokeWidth="2.5" strokeLinejoin="round" strokeLinecap="round" />
      {xs.map((x, i) => (
        <circle key={i} cx={x} cy={ys[i]} r="4" fill="#22d3ee" stroke="#07090f" strokeWidth="2" />
      ))}
      {data.map((d, i) => i % step === 0 && (
        <text key={i} x={xs[i]} y={H - 8} textAnchor="middle" fill="#6b7280" fontSize="10">{d.label}</text>
      ))}
    </svg>
  )
}

function HeroGraphic() {
  return (
    <svg width="260" height="130" viewBox="0 0 260 130" fill="none" className="dash-hero-graphic">
      <circle cx="100" cy="65" r="18" stroke="#3b82f6" strokeWidth="2" opacity="0.85" />
      <circle cx="100" cy="65" r="30" stroke="#3b82f6" strokeWidth="1.5" opacity="0.6" strokeDasharray="8 4" />
      <circle cx="100" cy="65" r="42" stroke="#3b82f6" strokeWidth="1.3" opacity="0.45" strokeDasharray="12 5" />
      <circle cx="100" cy="65" r="54" stroke="#3b82f6" strokeWidth="1.1" opacity="0.3" strokeDasharray="16 6" />
      <circle cx="100" cy="65" r="66" stroke="#3b82f6" strokeWidth="0.9" opacity="0.18" strokeDasharray="20 7" />
      <circle cx="100" cy="65" r="8" fill="rgba(59,130,246,.2)" stroke="#3b82f6" strokeWidth="1.5" />
      <circle cx="100" cy="65" r="3" fill="#3b82f6" />
      <circle cx="195" cy="88" r="26" stroke="#22d3ee" strokeWidth="2" fill="rgba(34,211,238,.07)" />
      <line x1="214" y1="107" x2="230" y2="123" stroke="#22d3ee" strokeWidth="3.5" strokeLinecap="round" />
      <circle cx="195" cy="88" r="14" stroke="#22d3ee" strokeWidth="1" opacity="0.4" />
      <line x1="40" y1="30" x2="68" y2="30" stroke="#3b82f6" strokeWidth="1" opacity="0.4" />
      <line x1="68" y1="30" x2="68" y2="12" stroke="#3b82f6" strokeWidth="1" opacity="0.4" />
      <circle cx="68" cy="12" r="2.5" fill="#3b82f6" opacity="0.5" />
      <line x1="148" y1="20" x2="172" y2="20" stroke="#22d3ee" strokeWidth="1" opacity="0.35" />
      <line x1="172" y1="20" x2="172" y2="40" stroke="#22d3ee" strokeWidth="1" opacity="0.35" />
      <circle cx="172" cy="40" r="2.5" fill="#22d3ee" opacity="0.4" />
      <line x1="30" y1="95" x2="50" y2="95" stroke="#3b82f6" strokeWidth="1" opacity="0.3" />
      <line x1="50" y1="95" x2="50" y2="115" stroke="#3b82f6" strokeWidth="1" opacity="0.3" />
      <circle cx="50" cy="115" r="2.5" fill="#3b82f6" opacity="0.35" />
    </svg>
  )
}

const STAT_CARDS = [
  {
    key: 'total', label: 'Total Cases',
    grad: 'linear-gradient(135deg,#1a3a6b,#1e4a8a)',
    iconBg: 'rgba(59,130,246,.25)', iconColor: '#93c5fd',
    icon: (
      <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/>
        <circle cx="14" cy="14" r="4"/><line x1="17" y1="17" x2="20" y2="20"/>
      </svg>
    )
  },
  {
    key: 'open', label: 'Open Cases',
    grad: 'linear-gradient(135deg,#0f4038,#0d5248)',
    iconBg: 'rgba(16,185,129,.25)', iconColor: '#6ee7b7',
    icon: (
      <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/>
        <polyline points="7 10 12 15 17 10"/>
      </svg>
    )
  },
  {
    key: 'active', label: 'Active Cases',
    grad: 'linear-gradient(135deg,#0a3a52,#0c4a68)',
    iconBg: 'rgba(34,211,238,.22)', iconColor: '#67e8f9',
    icon: (
      <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="10"/>
        <polygon points="10 8 16 12 10 16 10 8" fill="currentColor" strokeWidth="0"/>
      </svg>
    )
  },
  {
    key: 'closed', label: 'Closed Cases',
    grad: 'linear-gradient(135deg,#2d1a5c,#3a2278)',
    iconBg: 'rgba(167,139,250,.22)', iconColor: '#c4b5fd',
    icon: (
      <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <rect x="3" y="11" width="18" height="11" rx="2"/>
        <path d="M7 11V7a5 5 0 0110 0v4"/>
      </svg>
    )
  },
  {
    key: 'evidence', label: 'Evidence Items',
    grad: 'linear-gradient(135deg,#5a2e00,#7a3d00)',
    iconBg: 'rgba(245,158,11,.22)', iconColor: '#fcd34d',
    icon: (
      <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V7L14 2z"/>
        <polyline points="14 2 14 8 20 8"/>
        <line x1="9" y1="12" x2="15" y2="12"/><line x1="9" y1="16" x2="13" y2="16"/>
      </svg>
    )
  },
]

function useClock() {
  const [now, setNow] = useState(new Date())
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 60000)
    return () => clearInterval(t)
  }, [])
  return now
}

export default function Dashboard() {
  const { can } = useAuth()
  const [d, setD] = useState(null)
  const [recentCases, setRecentCases] = useState([])
  const now = useClock()

  useEffect(() => {
    api('/dashboard').then(setD)
    api('/cases?size=5').then(r => setRecentCases(r.items || [])).catch(() => {})
  }, [])

  if (!d) return <div className="empty">Loading…</div>

  const statValues = {
    total: d.cases.total,
    open: d.cases.open,
    active: d.cases.active,
    closed: d.cases.closed,
    evidence: d.evidence_total,
  }

  const dateStr = now.toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })
  const timeStr = now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })

  return (
    <>
      {/* Hero */}
      <div className="dash-hero">
        <div className="dash-hero-left">
          <h1 className="dash-hero-title">Dashboard</h1>
          <p className="dash-hero-sub">Welcome to DFIS — Monitor your digital forensic operations.</p>
          <div className="dash-hero-date">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>
            <span>{dateStr}</span>
            <span style={{ opacity: .6 }}>|</span>
            <span>{timeStr}</span>
          </div>
        </div>
        <HeroGraphic />
      </div>

      {/* Pending approvals alert */}
      {d.pending_approvals > 0 && (
        <div className="alert" style={{ marginBottom: 16 }}>
          ⚠ <strong>{d.pending_approvals} user account{d.pending_approvals > 1 ? 's' : ''}</strong> pending approval.{' '}
          <a href="#/users">Go to User Management →</a>
        </div>
      )}

      {/* Stat cards */}
      <div className="stat-cards">
        {STAT_CARDS.map(c => (
          <div key={c.key} className="stat-pro" style={{ background: c.grad }}>
            <div className="stat-icon-box" style={{ background: c.iconBg, color: c.iconColor }}>
              {c.icon}
            </div>
            <div className="stat-info">
              <div className="stat-num">{statValues[c.key] ?? 0}</div>
              <div className="stat-lbl">{c.label}</div>
              <div className="stat-trend">↑ +0</div>
            </div>
          </div>
        ))}
      </div>

      {/* Charts row */}
      <div className="grid two" style={{ marginBottom: 20 }}>
        <div className="card">
          <div className="section-header">
            <h2 className="section-title">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--cyan)" strokeWidth="2" strokeLinecap="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14" stroke="var(--cyan)"/></svg>
              Evidence Distribution
            </h2>
          </div>
          <DonutChart data={d.evidence_by_type} />
        </div>
        <div className="card">
          <div className="section-header">
            <h2 className="section-title">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--cyan)" strokeWidth="2" strokeLinecap="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12" stroke="var(--cyan)"/></svg>
              Investigation Activity (Last 14 Days)
            </h2>
          </div>
          <ActivityChart data={d.activity} />
        </div>
      </div>

      {/* Recent cases + Quick actions */}
      <div className="grid two" style={{ marginBottom: 20 }}>
        <div className="card">
          <div className="section-header">
            <h2 className="section-title">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--cyan)" strokeWidth="2" strokeLinecap="round"><path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z" stroke="var(--cyan)"/></svg>
              Recent Investigation Cases
            </h2>
            <a href="#/cases" style={{ fontSize: 12, color: 'var(--blue)' }}>View All →</a>
          </div>
          <Table
            cols={[
              { label: '#', render: (_, i) => i + 1 },
              { label: 'Case Name', render: r => <a href="#/cases">{r.ref}</a> },
              { label: 'Status', render: r => <Badge value={r.status} /> },
              { label: 'Evidence', render: r => r.evidence_count ?? '—' },
              { label: 'Last Updated', render: r => fmt(r.updated_at || r.created_at) },
            ]}
            rows={recentCases}
            empty="No cases yet."
          />
        </div>

        <div className="card">
          <div className="section-header">
            <h2 className="section-title">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--cyan)" strokeWidth="2" strokeLinecap="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" stroke="var(--cyan)"/></svg>
              Quick Actions
            </h2>
          </div>
          <div className="qa-grid">
            <a href="#/cases" className="qa-btn" style={{ background: 'linear-gradient(135deg,#1a3a6b,#1e4a8a)' }}>
              <div className="qa-icon">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#93c5fd" strokeWidth="2" strokeLinecap="round"><path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/><line x1="12" y1="11" x2="12" y2="17"/><line x1="9" y1="14" x2="15" y2="14"/></svg>
              </div>
              New Investigation
            </a>
            <a href="#/evidence" className="qa-btn" style={{ background: 'linear-gradient(135deg,#0f4038,#0d5248)' }}>
              <div className="qa-icon">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#6ee7b7" strokeWidth="2" strokeLinecap="round"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
              </div>
              Upload Evidence
            </a>
            <a href="#/analysis" className="qa-btn" style={{ background: 'linear-gradient(135deg,#2d1a5c,#3a2278)' }}>
              <div className="qa-icon">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#c4b5fd" strokeWidth="2" strokeLinecap="round"><circle cx="11" cy="11" r="7"/><line x1="17" y1="17" x2="22" y2="22"/></svg>
              </div>
              Analyze Files
            </a>
            <a href="#/reports" className="qa-btn" style={{ background: 'linear-gradient(135deg,#5a2e00,#7a3d00)' }}>
              <div className="qa-icon">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#fcd34d" strokeWidth="2" strokeLinecap="round"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V7L14 2z"/><polyline points="14 2 14 8 20 8"/><line x1="9" y1="12" x2="15" y2="12"/></svg>
              </div>
              Generate Report
            </a>
          </div>
        </div>
      </div>

      {/* Integrity + Custody */}
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
