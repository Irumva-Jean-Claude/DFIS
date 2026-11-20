import { useState, useEffect, useCallback } from 'react'
import { api, fmt, qs } from '../api'
import { useAuth } from '../context/AuthContext'
import { useToast } from '../context/ToastContext'
import Badge from '../components/Badge'
import Table from '../components/Table'
import Modal from '../components/Modal'

export default function Timeline() {
  const { can } = useAuth()
  const toast = useToast()
  const [cases, setCases] = useState([])
  const [caseId, setCaseId] = useState('')
  const [evidence, setEvidence] = useState([])
  const [eid, setEid] = useState('')
  const [category, setCategory] = useState('')
  const [order, setOrder] = useState('asc')
  const [items, setItems] = useState([])
  const [undated, setUndated] = useState([])
  const [truncated, setTruncated] = useState(false)
  const [adding, setAdding] = useState(false)

  useEffect(() => { api('/cases?size=100').then(r => setCases(r.items)).catch(() => {}) }, [])

  const loadEvidence = useCallback(async () => {
    if (!caseId) { setEvidence([]); return }
    try {
      const r = await api('/evidence?' + qs({ case_id: caseId, size: 100 }))
      setEvidence(r.items)
    } catch {}
  }, [caseId])

  useEffect(() => { loadEvidence() }, [loadEvidence])

  const loadTimeline = useCallback(async () => {
    if (!caseId) { setItems([]); setUndated([]); return }
    try {
      const r = await api('/timeline?' + qs({ case_id: caseId, evidence_id: eid, category, order }))
      setItems(r.items); setUndated(r.undated); setTruncated(r.truncated)
    } catch (err) { toast(err.message, true) }
  }, [caseId, eid, category, order])

  useEffect(() => { loadTimeline() }, [loadTimeline])

  const addEvent = async e => {
    e.preventDefault()
    const fd = new FormData(e.target)
    const body = { case_id: caseId, title: fd.get('title'), details: fd.get('details'), original_ts: fd.get('original_ts') }
    if (fd.get('evidence_id')) body.evidence_id = fd.get('evidence_id')
    try {
      await api('/timeline', { method: 'POST', body }); toast('Event added')
      setAdding(false); loadTimeline()
    } catch (err) { toast(err.message, true) }
  }

  const catColor = { analyst: 'active', metadata: 'open', acquisition: 'closed', custody: 'medium', log: 'low' }

  return (
    <>
      <h1>Timeline Analysis</h1>
      <div className="row">
        <select value={caseId} onChange={e => { setCaseId(e.target.value); setEid(''); setItems([]) }}>
          <option value="">Select a case…</option>
          {cases.map(c => <option key={c.id} value={c.id}>{c.ref} — {c.title}</option>)}
        </select>
        <select value={eid} onChange={e => setEid(e.target.value)}>
          <option value="">All evidence</option>
          {evidence.map(e => <option key={e.id} value={e.id}>{e.ref}</option>)}
        </select>
        <select value={category} onChange={e => setCategory(e.target.value)}>
          <option value="">All categories</option>
          {['analyst', 'metadata', 'acquisition', 'custody', 'log'].map(c => <option key={c}>{c}</option>)}
        </select>
        <select value={order} onChange={e => setOrder(e.target.value)}>
          <option value="asc">Oldest first</option>
          <option value="desc">Newest first</option>
        </select>
        <span className="spacer" />
        {caseId && can('timeline:write') && <button className="btn primary" onClick={() => setAdding(true)}>Add event</button>}
      </div>

      {truncated && <div className="note">Result truncated — apply filters to narrow the view.</div>}

      <div className="card">
        <Table
          cols={[
            { label: 'UTC time', render: r => r.utc ? fmt(r.utc) : '—' },
            { label: 'Category', render: r => <Badge value={catColor[r.category] || r.category} /> },
            { label: 'Event', render: r => <strong>{r.title}</strong> },
            { label: 'Details', render: r => <span style={{ fontSize: 12 }}>{r.details}</span> },
            { label: 'Evidence', render: r => r.evidence_ref || '—' },
            { label: 'Note', render: r => <span style={{ fontSize: 11, color: 'var(--muted)' }}>{r.note}</span> },
          ]}
          rows={items} empty={caseId ? 'No dated events.' : 'Select a case to view the timeline.'} />
      </div>

      {undated.length > 0 && (
        <div className="card">
          <h2>Undated / unparseable events ({undated.length})</h2>
          <Table
            cols={[
              { label: 'Category', render: r => <Badge value={r.category} /> },
              { label: 'Event', render: r => r.title },
              { label: 'Original timestamp', render: r => r.original || '—' },
            ]}
            rows={undated} empty="" />
        </div>
      )}

      {adding && (
        <Modal title="Add analyst event" onClose={() => setAdding(false)}>
          <form onSubmit={addEvent}>
            <label>Title<input name="title" required minLength={3} maxLength={200} /></label>
            <label>Timestamp (ISO-8601 or natural date)<input name="original_ts" required placeholder="e.g. 2024-06-01T14:30:00Z" /></label>
            <label>Details<textarea name="details" rows={3} maxLength={3000} /></label>
            <label>Evidence (optional)
              <select name="evidence_id">
                <option value="">None</option>
                {evidence.map(e => <option key={e.id} value={e.id}>{e.ref} — {e.original_filename}</option>)}
              </select>
            </label>
            <button className="btn primary">Add</button>
          </form>
        </Modal>
      )}
    </>
  )
}
