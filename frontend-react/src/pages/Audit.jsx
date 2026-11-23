import { useState, useEffect, useCallback } from 'react'
import { api, fmt, qs } from '../api'
import { useAuth } from '../context/AuthContext'
import { useToast } from '../context/ToastContext'
import Badge from '../components/Badge'
import Table from '../components/Table'
import Pager from '../components/Pager'

export default function Audit() {
  const { can } = useAuth()
  const toast = useToast()
  const [items, setItems] = useState([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [q, setQ] = useState('')
  const [action, setAction] = useState('')
  const [chainStatus, setChainStatus] = useState(null)
  const [verifying, setVerifying] = useState(false)
  const SIZE = 20

  const load = useCallback(async () => {
    try {
      const r = await api('/audit?' + qs({ q, action, page, size: SIZE }))
      setItems(r.items); setTotal(r.total)
    } catch (err) { toast(err.message, true) }
  }, [q, action, page])

  useEffect(() => { load() }, [load])

  const verifyChain = async () => {
    setVerifying(true); setChainStatus(null)
    try {
      const r = await api('/audit/verify')
      setChainStatus(r)
    } catch (err) { toast(err.message, true) }
    finally { setVerifying(false) }
  }

  return (
    <>
      <h1>Audit Trail</h1>
      <div className="row">
        <input placeholder="Search actor or action" value={q} onChange={e => { setQ(e.target.value); setPage(1) }} />
        <input placeholder="Exact action" value={action} onChange={e => { setAction(e.target.value); setPage(1) }} />
        <span className="spacer" />
        {can('users:manage') && (
          <button className="btn" onClick={verifyChain} disabled={verifying}>{verifying ? 'Verifying…' : 'Verify chain'}</button>
        )}
      </div>

      {chainStatus && (
        chainStatus.valid ? (
          <div className="note" style={{ marginBottom: 8, color: 'var(--green)', borderColor: 'rgba(16,185,129,.3)', background: 'var(--green-bg)' }}>
            ✓ Audit chain intact — all {chainStatus.checked} events verified. No tampering detected.
          </div>
        ) : (
          <div className="error" style={{ marginBottom: 8 }}>
            ✗ Audit chain broken at event #{chainStatus.broken_at_seq}
            {chainStatus.action && <> (<b>{chainStatus.action}</b>{chainStatus.ts && <>, {fmt(chainStatus.ts)}</>})</>}
            : {chainStatus.reason}. {chainStatus.checked} earlier event(s) verified OK.
          </div>
        )
      )}

      <div className="card">
        <Table
          cols={[
            { label: 'Seq', render: r => r.seq },
            { label: 'Time', render: r => fmt(r.ts) },
            { label: 'Actor', render: r => r.actor || '—' },
            { label: 'Action', render: r => r.action },
            { label: 'Object', render: r => r.object_type ? `${r.object_type}/${r.object_id?.slice(0, 8) || ''}` : '—' },
            { label: 'Outcome', render: r => <Badge value={r.outcome} /> },
          ]}
          rows={items}
          empty="No audit events visible."
        />
        <Pager page={page} size={SIZE} total={total} onChange={p => setPage(p)} />
      </div>
    </>
  )
}
