import { useState, useEffect, useCallback } from 'react'
import { useLocation } from 'react-router-dom'
import { api, fmt, qs, download } from '../api'
import { useAuth } from '../context/AuthContext'
import { useToast } from '../context/ToastContext'
import Badge from '../components/Badge'
import Table from '../components/Table'
import Pager from '../components/Pager'
import Modal from '../components/Modal'
import KeyValue from '../components/KeyValue'

const TYPES = ['document', 'image', 'disk_image', 'memory_dump', 'network_capture', 'log_file', 'archive', 'other']

function EvidenceDetail({ id, onClose, onRefresh }) {
  const { can } = useAuth()
  const toast = useToast()
  const [e, setE] = useState(null)
  const [hist, setHist] = useState([])
  const [checking, setChecking] = useState(false)
  const [vtResult, setVtResult] = useState(null)
  const [vtLoading, setVtLoading] = useState(false)

  const load = useCallback(() =>
    Promise.all([api('/evidence/' + id), api('/integrity/' + id)])
      .then(([ev, h]) => {
        setE(ev)
        setHist(h)
        if (ev.vt_status) setVtResult({
          status: ev.vt_status, malicious: ev.vt_malicious,
          suspicious: ev.vt_suspicious, total_engines: ev.vt_total_engines,
          undetected: ev.vt_total_engines - ev.vt_malicious - ev.vt_suspicious,
          message: ev.vt_message, scanned_at: ev.vt_scanned_at
        })
      })
  , [id])

  useEffect(() => { load() }, [load])

  if (!e) return <Modal title="Loading…" onClose={onClose}><p className="muted">Loading…</p></Modal>

  const verify = async () => {
    setChecking(true)
    try {
      const r = await api('/integrity/' + id + '/verify', { method: 'POST' })
      toast(`Integrity: ${r.result} — ${r.message}`)
      load()
    } catch (err) { toast(err.message, true) }
    finally { setChecking(false) }
  }

  const handleDownload = () => download('/evidence/' + id + '/download', e.original_filename)

  const scanVT = async () => {
    setVtLoading(true); setVtResult(null)
    try {
      const r = await api('/integrity/' + id + '/virustotal')
      setVtResult(r)
    } catch (err) { toast(err.message, true) }
    finally { setVtLoading(false) }
  }

  return (
    <Modal title={`${e.ref} — ${e.original_filename}`} onClose={onClose} wide>
      <div className="row"><Badge value={e.status} /> <Badge value={e.evidence_type} /></div>
      <KeyValue data={{
        Case: e.case_ref, MIME: e.mime, Size: `${e.size} bytes`,
        'SHA-256': e.sha256, Description: e.description,
        Source: e.source, 'Acquisition method': e.acquisition_method,
        'Acquisition date': e.acquisition_date || '—', Custodian: e.custodian,
        'Submitted by': e.submitted_by, 'Received by': e.received_by,
        'Registered': fmt(e.created_at),
      }} />
      {e.mime?.startsWith('image/') && (
        <img src={`/api/v1/evidence/${id}/preview`} alt={e.original_filename}
          style={{ maxWidth: '100%', marginTop: 8 }}
          onError={ev => ev.target.style.display = 'none'} />
      )}
      <div className="row" style={{ marginTop: 12 }}>
        <button className="btn sm" onClick={handleDownload}>Download original</button>
        {can('analysis:run') && <button className="btn sm" onClick={verify} disabled={checking}>{checking ? 'Verifying…' : 'Verify integrity'}</button>}
        {can('analysis:run') && <button className="btn sm primary" onClick={scanVT} disabled={vtLoading}>{vtLoading ? 'Scanning… (up to 30s)' : '🔍 Scan with VirusTotal'}</button>}
      </div>
      {vtResult && (
        <div style={{
          marginTop: 12, padding: '12px 16px', borderRadius: 6, border: '1px solid',
          borderColor: vtResult.status === 'malicious' ? '#c0392b' : vtResult.status === 'suspicious' ? '#e67e22' : '#27ae60',
          background: vtResult.status === 'malicious' ? '#2a0a0a' : vtResult.status === 'suspicious' ? '#2a1a0a' : '#0a2a0a',
        }}>
          <strong style={{ color: vtResult.status === 'malicious' ? '#e74c3c' : vtResult.status === 'suspicious' ? '#e67e22' : '#2ecc71' }}>
            {vtResult.status === 'malicious' ? '⚠️ MALWARE DETECTED' : vtResult.status === 'suspicious' ? '⚠️ SUSPICIOUS' : vtResult.status === 'not_found' ? 'ℹ️ NOT IN DATABASE' : '✅ CLEAN'}
          </strong>
          <p style={{ margin: '4px 0 0', fontSize: 13 }}>{vtResult.message}</p>
          {vtResult.total_engines > 0 && (
            <p style={{ margin: '4px 0 0', fontSize: 12, opacity: 0.7 }}>
              Malicious: {vtResult.malicious} &nbsp;|&nbsp; Suspicious: {vtResult.suspicious} &nbsp;|&nbsp; Clean: {vtResult.undetected} &nbsp;|&nbsp; Total engines: {vtResult.total_engines}
            </p>
          )}
          {vtResult.scanned_at && (
            <p style={{ margin: '4px 0 0', fontSize: 11, opacity: 0.5 }}>Last scanned: {fmt(vtResult.scanned_at)}</p>
          )}
        </div>
      )}
      {hist.length > 0 && (
        <>
          <h3>Integrity checks</h3>
          <Table
            cols={[
              { label: 'Result', render: r => <Badge value={r.result} /> },
              { label: 'By', render: r => r.by_user },
              { label: 'Time', render: r => fmt(r.at) },
            ]}
            rows={hist} empty="No checks yet." />
        </>
      )}
    </Modal>
  )
}

export default function Evidence() {
  const { can } = useAuth()
  const toast = useToast()
  const loc = useLocation()
  const [items, setItems] = useState([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [q, setQ] = useState(() => new URLSearchParams(loc.search).get('q') || '')
  const [caseId, setCaseId] = useState('')
  const [etype, setEtype] = useState('')
  const [cases, setCases] = useState([])
  const [selected, setSelected] = useState(null)
  const [uploading, setUploading] = useState(false)
  const SIZE = 10

  const load = useCallback(async () => {
    try {
      const r = await api('/evidence?' + qs({ q, case_id: caseId, evidence_type: etype, page, size: SIZE }))
      setItems(r.items); setTotal(r.total)
    } catch (err) { toast(err.message, true) }
  }, [q, caseId, etype, page])

  useEffect(() => { load() }, [load])
  useEffect(() => { api('/cases?size=100').then(r => setCases(r.items)).catch(() => {}) }, [])

  const handleUpload = async e => {
    e.preventDefault()
    const fd = new FormData(e.target)
    try {
      await api('/evidence', { method: 'POST', form: fd })
      toast('Evidence registered'); setUploading(false); load()
    } catch (err) { toast(err.message, true) }
  }

  const exportCsv = () => download('/evidence/export?' + qs({ case_id: caseId }), 'evidence_inventory.csv')

  return (
    <>
      <h1>Digital Evidence</h1>
      <div className="row">
        <input placeholder="Search ref, filename or hash" value={q} onChange={e => { setQ(e.target.value); setPage(1) }} />
        <select value={caseId} onChange={e => { setCaseId(e.target.value); setPage(1) }}>
          <option value="">All cases</option>
          {cases.map(c => <option key={c.id} value={c.id}>{c.ref} — {c.title}</option>)}
        </select>
        <select value={etype} onChange={e => { setEtype(e.target.value); setPage(1) }}>
          <option value="">All types</option>
          {TYPES.map(t => <option key={t}>{t}</option>)}
        </select>
        <span className="spacer" />
        <button className="btn" onClick={exportCsv}>Export CSV</button>
        {can('evidence:upload') && <button className="btn primary" onClick={() => setUploading(true)}>Register evidence</button>}
      </div>

      <div className="card">
        <Table
          cols={[
            { label: 'Ref', render: r => <a href="#" onClick={ev => { ev.preventDefault(); setSelected(r.id) }}>{r.ref}</a> },
            { label: 'File', render: r => r.original_filename },
            { label: 'Type', render: r => <Badge value={r.evidence_type} /> },
            { label: 'Case', render: r => r.case_ref },
            { label: 'Status', render: r => <Badge value={r.status} /> },
            { label: 'Size', render: r => r.size },
            { label: 'Registered', render: r => fmt(r.created_at) },
          ]}
          rows={items}
          empty="No evidence items found."
        />
        <Pager page={page} size={SIZE} total={total} onChange={p => setPage(p)} />
      </div>

      {selected && <EvidenceDetail id={selected} onClose={() => setSelected(null)} onRefresh={load} />}

      {uploading && (
        <Modal title="Register evidence" onClose={() => setUploading(false)} wide>
          <form onSubmit={handleUpload} encType="multipart/form-data">
            <label>Case
              <select name="case_id" required>
                <option value="">Select case…</option>
                {cases.map(c => <option key={c.id} value={c.id}>{c.ref} — {c.title}</option>)}
              </select>
            </label>
            <label>Evidence type
              <select name="evidence_type" required>
                {TYPES.map(t => <option key={t}>{t}</option>)}
              </select>
            </label>
            <label>Source (location/device found on)<input name="source" required maxLength={200} /></label>
            <label>Acquisition method<input name="acquisition_method" required maxLength={200} /></label>
            <label>Acquisition date (optional)<input name="acquisition_date" placeholder="e.g. 2024-06-01T14:00:00" /></label>
            <label>Submitted by<input name="submitted_by" required maxLength={100} /></label>
            <label>Received by<input name="received_by" required maxLength={100} /></label>
            <label>Description<textarea name="description" rows={2} maxLength={2000} /></label>
            <label>File<input type="file" name="file" required /></label>
            <button className="btn primary">Register</button>
          </form>
        </Modal>
      )}
    </>
  )
}
