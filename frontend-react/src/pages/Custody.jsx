import { useState, useEffect, useCallback } from 'react'
import { api, fmt, qs } from '../api'
import { useAuth } from '../context/AuthContext'
import { useToast } from '../context/ToastContext'
import Badge from '../components/Badge'
import Table from '../components/Table'
import Modal from '../components/Modal'
import KeyValue from '../components/KeyValue'

export default function Custody() {
  const { can, me } = useAuth()
  const [cancelling, setCancelling] = useState(null)
  const toast = useToast()
  const [cases, setCases] = useState([])
  const [caseId, setCaseId] = useState('')
  const [evidence, setEvidence] = useState([])
  const [selected, setSelected] = useState(null)
  const [record, setRecord] = useState(null)
  const [transferOpen, setTransferOpen] = useState(false)
  const [dir, setDir] = useState([])

  useEffect(() => { api('/cases?size=100').then(r => setCases(r.items)).catch(() => {}) }, [])
  useEffect(() => { api('/users/directory').then(setDir).catch(() => {}) }, [])

  const loadEvidence = useCallback(async () => {
    if (!caseId) { setEvidence([]); return }
    try {
      const r = await api('/evidence?' + qs({ case_id: caseId, size: 100 }))
      setEvidence(r.items)
    } catch {}
  }, [caseId])

  useEffect(() => { loadEvidence() }, [loadEvidence])

  const loadRecord = useCallback(async id => {
    try {
      const r = await api('/chain-of-custody/' + id)
      setRecord(r)
    } catch (err) { toast(err.message, true) }
  }, [])

  const selectEvidence = id => { setSelected(id); loadRecord(id) }

  const acknowledge = async eventId => {
    if (!confirm('Acknowledge receipt of this transfer?')) return
    try {
      await api('/chain-of-custody/' + selected + '/acknowledge/' + eventId, { method: 'POST' })
      toast('Transfer acknowledged'); loadRecord(selected)
    } catch (err) { toast(err.message, true) }
  }

  const canCancel = r => can('custody:transfer') &&
    (['admin', 'lead'].includes(me?.role) || [r.by_user_id, r.from_user_id].includes(me?.id))

  const cancelTransfer = async e => {
    e.preventDefault()
    const reason = new FormData(e.target).get('reason')
    try {
      await api('/chain-of-custody/' + selected + '/cancel/' + cancelling.id, { method: 'POST', body: { reason } })
      toast('Transfer cancelled — evidence returned to ' + (cancelling.from_user || 'the custodian'))
      setCancelling(null); loadRecord(selected)
    } catch (err) { toast(err.message, true) }
  }

  const transfer = async e => {
    e.preventDefault()
    const fd = new FormData(e.target)
    try {
      await api('/chain-of-custody/' + selected + '/transfer', { method: 'POST', body: Object.fromEntries(fd) })
      toast('Transfer initiated'); setTransferOpen(false); loadRecord(selected)
    } catch (err) { toast(err.message, true) }
  }

  const ev = record?.evidence

  return (
    <>
      <h1>Chain of Custody</h1>
      <div className="row">
        <select value={caseId} onChange={e => { setCaseId(e.target.value); setSelected(null); setRecord(null) }}>
          <option value="">Select a case…</option>
          {cases.map(c => <option key={c.id} value={c.id}>{c.ref} — {c.title}</option>)}
        </select>
        {caseId && (
          <select value={selected || ''} onChange={e => selectEvidence(e.target.value)}>
            <option value="">Select evidence…</option>
            {evidence.map(e => <option key={e.id} value={e.id}>{e.ref} — {e.original_filename}</option>)}
          </select>
        )}
        <span className="spacer" />
        {selected && can('custody:transfer') && <button className="btn primary" onClick={() => setTransferOpen(true)}>Transfer custody</button>}
      </div>

      {ev && (
        <div className="card">
          <h2>{ev.ref} — {ev.original_filename}</h2>
          <div className="row"><Badge value={ev.status} /> <span className="muted">Custodian: {ev.custodian || '—'}</span></div>
        </div>
      )}

      {record && (
        <div className="card">
          <h2>Custody chain</h2>
          <Table
            cols={[
              { label: 'Time (UTC)', render: r => fmt(r.created_at) },
              { label: 'Action', render: r => <Badge value={r.action} /> },
              { label: 'By', render: r => r.by_user || '—' },
              { label: 'From', render: r => r.from_user || '—' },
              { label: 'To', render: r => r.to_user || '—' },
              { label: 'Reason', render: r => r.reason },
              {
                label: 'Status', render: r => {
                  if (!r.ack_status) return null
                  if (r.ack_status !== 'pending') return <Badge value={r.ack_status} />
                  const mine = r.to_user_id === me?.id
                  return (
                    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
                      {mine
                        ? <button className="btn sm primary" onClick={() => acknowledge(r.id)}>Acknowledge</button>
                        : <span className="muted" style={{ fontSize: 12 }}>Awaiting {r.to_user || 'recipient'}</span>}
                      {canCancel(r) && <button className="btn sm" onClick={() => setCancelling(r)}>Cancel transfer</button>}
                    </div>
                  )
                }
              },
            ]}
            rows={record.events} empty="No custody events." />
        </div>
      )}

      {cancelling && (
        <Modal title="Cancel custody transfer" onClose={() => setCancelling(null)}>
          <form onSubmit={cancelTransfer}>
            <p className="muted" style={{ marginBottom: 12, fontSize: 13 }}>
              The transfer to <b>{cancelling.to_user}</b> will be cancelled and the evidence stays with{' '}
              <b>{cancelling.from_user || 'the current custodian'}</b>. Nothing is deleted: a
              TRANSFER_CANCELLED entry with your reason is added to the custody chain and the audit trail.
            </p>
            <label>Reason for cancelling
              <input name="reason" required minLength={5} maxLength={1000} placeholder="e.g. Wrong recipient selected" autoFocus />
            </label>
            <button className="btn primary">Cancel transfer</button>
          </form>
        </Modal>
      )}

      {transferOpen && (
        <Modal title="Transfer custody" onClose={() => setTransferOpen(false)}>
          <form onSubmit={transfer}>
            <label>Transfer to
              <select name="to_user_id" required>
                <option value="">Select investigator…</option>
                {dir.map(u => <option key={u.id} value={u.id}>{u.full_name} ({u.role})</option>)}
              </select>
            </label>
            <label>Reason<input name="reason" required minLength={3} maxLength={1000} /></label>
            <label>Notes<textarea name="notes" rows={2} maxLength={2000} /></label>
            <button className="btn primary">Transfer</button>
          </form>
        </Modal>
      )}
    </>
  )
}
