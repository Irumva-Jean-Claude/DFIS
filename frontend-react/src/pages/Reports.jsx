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

function VerifyPanel() {
  const toast = useToast()
  const [file, setFile] = useState(null)
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState(null)

  const verify = async e => {
    e.preventDefault()
    if (!file) return
    setBusy(true); setResult(null)
    try {
      const fd = new FormData(); fd.append('file', file)
      setResult(await api('/reports/verify', { method: 'POST', form: fd }))
    } catch (err) { toast(err.message, true) }
    finally { setBusy(false) }
  }

  const ok = result?.authentic
  return (
    <div className="card">
      <h2>Verify report</h2>
      <p className="muted" style={{ marginBottom: 12, fontSize: 13 }}>
        Upload a PDF report to check that it was issued by DFIS and has not been modified since.
        Any change to the file, even one character, fails verification.
      </p>
      <form className="row" onSubmit={verify}>
        <input type="file" accept="application/pdf,.pdf" onChange={e => { setFile(e.target.files[0] || null); setResult(null) }} />
        <button className="btn primary" disabled={!file || busy}>{busy ? 'Verifying…' : 'Verify'}</button>
      </form>
      {result && (
        <div style={{
          marginTop: 14, padding: '14px 18px', borderRadius: 'var(--radius-sm)', fontSize: 13, lineHeight: 1.7,
          border: `1px solid ${ok ? 'rgba(16,185,129,.35)' : 'rgba(244,63,94,.35)'}`,
          background: ok ? 'var(--green-bg)' : 'var(--red-bg)',
        }}>
          <div style={{ fontWeight: 700, fontSize: 15, color: ok ? 'var(--green)' : 'var(--red)', marginBottom: 4 }}>
            {ok ? '✓ Authentic report' : '✗ Verification failed'}
          </div>
          <div>{result.message}</div>
          {ok && (
            <div className="muted" style={{ marginTop: 6 }}>
              {result.ref} v{result.version} · case {result.case_ref} · issued by {result.issued_by} on {fmt(result.issued_at)}
            </div>
          )}
          <div className="muted" style={{ marginTop: 6, fontFamily: 'monospace', fontSize: 11, wordBreak: 'break-all' }}>
            SHA-256 of uploaded file: {result.sha256}
            {result.expected_sha256 && <><br />SHA-256 of issued report: {result.expected_sha256}</>}
          </div>
        </div>
      )}
    </div>
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
            { label: 'Seal', render: r => r.signed
              ? <span title={'SHA-256: ' + r.sha256} style={{ color: 'var(--green)', fontWeight: 600 }}>✓ Sealed</span>
              : <span className="muted" title="Generated before report sealing was enabled">Not sealed</span> },
            { label: '', render: r => <button className="btn sm" onClick={() => download('/reports/' + r.id + '/download', `${r.ref}_v${r.version}.pdf`)}>PDF</button> },
          ]}
          rows={reports} empty="No reports generated yet." />
      </div>

      {can('report:read') && <VerifyPanel />}

      {preview && <PreviewModal preview={preview} onClose={() => setPreview(null)} onGenerate={generate} />}
    </>
  )
}
