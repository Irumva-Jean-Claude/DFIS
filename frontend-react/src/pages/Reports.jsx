import { useState, useEffect } from 'react'
import { api, fmt, qs, download } from '../api'
import { useAuth } from '../context/AuthContext'
import { useToast } from '../context/ToastContext'
import Table from '../components/Table'
import Modal from '../components/Modal'
import KeyValue from '../components/KeyValue'

function PreviewModal({ preview, onClose, onGenerate }) {
  const [conclusions, setConclusions] = useState('')
  const [limitations, setLimitations] = useState('')
  const [notes, setNotes] = useState('')

  const p = preview
  return (
    <Modal title={`Report preview — ${p.case.ref}`} onClose={onClose} wide>
      <KeyValue data={{
        Case: `${p.case.ref} — ${p.case.title}`,
        Status: p.case.status,
        Investigators: p.investigators.join(', '),
        'Evidence items': p.evidence.length,
        'Timeline events': p.timeline_events,
        'Next version': `v${p.next_version}`,
      }} />
      <h3>Evidence summary</h3>
      <Table
        cols={[
          { label: 'Ref', render: r => r.ref },
          { label: 'File', render: r => r.file },
          { label: 'SHA-256', render: r => <span style={{ fontSize: 11 }}>{r.sha256?.slice(0, 16)}…</span> },
          { label: 'Integrity', render: r => r.last_integrity },
          { label: 'File analysis', render: r => r.file_analysis },
          { label: 'Custody events', render: r => r.custody_events },
        ]}
        rows={p.evidence} empty="No evidence." />
      <h3>Report content</h3>
      <label>Limitations<textarea value={limitations} onChange={e => setLimitations(e.target.value)} rows={3} maxLength={8000} /></label>
      <label>Notes<textarea value={notes} onChange={e => setNotes(e.target.value)} rows={3} maxLength={8000} /></label>
      <label>Conclusions<textarea value={conclusions} onChange={e => setConclusions(e.target.value)} rows={3} maxLength={8000} /></label>
      <button className="btn primary" onClick={() => onGenerate(conclusions, limitations, notes)}>Generate PDF</button>
    </Modal>
  )
}

export default function Reports() {
  const { can } = useAuth()
  const toast = useToast()
  const [cases, setCases] = useState([])
  const [caseId, setCaseId] = useState('')
  const [reports, setReports] = useState([])
  const [preview, setPreview] = useState(null)
  const [generating, setGenerating] = useState(false)

  useEffect(() => { api('/cases?size=100').then(r => setCases(r.items)).catch(() => {}) }, [])

  const loadReports = async (cid = caseId) => {
    try {
      const r = await api('/reports?' + qs({ case_id: cid }))
      setReports(r)
    } catch (err) { toast(err.message, true) }
  }

  useEffect(() => { loadReports() }, [caseId])

  const openPreview = async () => {
    if (!caseId) { toast('Select a case first', true); return }
    try {
      const p = await api('/reports/preview', { method: 'POST', body: { case_id: caseId, conclusions: '', limitations: '', notes: '' } })
      setPreview(p)
    } catch (err) { toast(err.message, true) }
  }

  const generate = async (conclusions, limitations, notes) => {
    setGenerating(true)
    try {
      await api('/reports', { method: 'POST', body: { case_id: caseId, conclusions, limitations, notes } })
      toast('Report generated'); setPreview(null); loadReports()
    } catch (err) { toast(err.message, true) }
    finally { setGenerating(false) }
  }

  return (
    <>
      <h1>Forensic Reports</h1>
      <div className="row">
        <select value={caseId} onChange={e => setCaseId(e.target.value)}>
          <option value="">All cases</option>
          {cases.map(c => <option key={c.id} value={c.id}>{c.ref} — {c.title}</option>)}
        </select>
        <span className="spacer" />
        {can('report:create') && <button className="btn primary" onClick={openPreview}>New report…</button>}
      </div>

      <div className="card">
        <Table
          cols={[
            { label: 'Report ref', render: r => r.ref },
            { label: 'Case', render: r => r.case_ref },
            { label: 'Version', render: r => `v${r.version}` },
            { label: 'By', render: r => r.by_user },
            { label: 'Created', render: r => fmt(r.created_at) },
            { label: '', render: r => <button className="btn sm" onClick={() => download('/reports/' + r.id + '/download', `${r.ref}_v${r.version}.pdf`)}>PDF</button> },
          ]}
          rows={reports} empty="No reports generated yet." />
      </div>

      {preview && <PreviewModal preview={preview} onClose={() => setPreview(null)} onGenerate={generate} />}
    </>
  )
}
