import { useState, useEffect, useCallback } from 'react'
import { api, fmt, qs, download } from '../api'
import { useAuth } from '../context/AuthContext'
import { useToast } from '../context/ToastContext'
import Badge from '../components/Badge'
import Table from '../components/Table'
import Pager from '../components/Pager'

export default function LogAnalysis() {
  const { can } = useAuth()
  const toast = useToast()
  const [cases, setCases] = useState([])
  const [caseId, setCaseId] = useState('')
  const [evidence, setEvidence] = useState([])
  const [selected, setSelected] = useState(null)
  const [jobs, setJobs] = useState([])
  const [running, setRunning] = useState(false)
  const [events, setEvents] = useState([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [q, setQ] = useState('')
  const [etype, setEtype] = useState('')
  const [source, setSource] = useState('')
  const [mlRunning, setMlRunning] = useState(false)
  const [mlResult, setMlResult] = useState(null)
  const SIZE = 25

  useEffect(() => { api('/cases?size=100').then(r => setCases(r.items)).catch(() => {}) }, [])

  const loadEvidence = useCallback(async () => {
    if (!caseId) { setEvidence([]); return }
    try {
      const r = await api('/evidence?' + qs({ case_id: caseId, size: 100 }))
      setEvidence(r.items.filter(e => e.evidence_type === 'log_file' || e.mime?.includes('text')))
    } catch (err) { toast(err.message, true) }
  }, [caseId])

  useEffect(() => { loadEvidence() }, [loadEvidence])

  const loadEvents = useCallback(async () => {
    if (!selected) return
    try {
      const r = await api('/log-analysis/' + selected + '/events?' + qs({ q, event_type: etype, source, page, size: SIZE }))
      setEvents(r.items); setTotal(r.total)
    } catch (err) { toast(err.message, true) }
  }, [selected, q, etype, source, page])

  useEffect(() => { loadEvents() }, [loadEvents])

  const selectEvidence = async id => {
    setSelected(id); setPage(1); setQ(''); setEtype(''); setSource('')
    try {
      const h = await api('/log-analysis/' + id + '/summary')
      setJobs(h)
    } catch { setJobs([]) }
  }

  const runLog = async () => {
    if (!selected) return
    setRunning(true)
    try {
      await api('/log-analysis/' + selected, { method: 'POST' })
      toast('Log analysis complete')
      const h = await api('/log-analysis/' + selected + '/summary')
      setJobs(h); loadEvents()
    } catch (err) { toast(err.message, true) }
    finally { setRunning(false) }
  }

  const runMlScan = async () => {
    setMlRunning(true); setMlResult(null)
    try {
      const r = await api('/ml/intrusion-detect', { method: 'POST' })
      setMlResult(r)
      toast('AI scan complete — ' + r.attacks_detected + ' attack(s) detected')
    } catch (err) { toast(err.message, true) }
    finally { setMlRunning(false) }
  }

  const exportCsv = () => {
    if (!selected) return
    download('/log-analysis/' + selected + '/export?' + qs({ q, event_type: etype, source }), 'log_events.csv')
  }

  const latestJob = jobs[0]
  const stats = latestJob?.result?.stats
  const alerts = latestJob?.result?.alerts || []

  return (
    <>
      <h1>Log Analysis</h1>
      <div className="row">
        <select value={caseId} onChange={e => { setCaseId(e.target.value); setSelected(null); setJobs([]) }}>
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
        {selected && can('analysis:run') && <button className="btn primary" onClick={runLog} disabled={running}>{running ? 'Parsing…' : 'Parse log'}</button>}
        {selected && <button className="btn" onClick={exportCsv}>Export CSV</button>}
      </div>

      {latestJob && (
        <div className="card">
          <h2>Latest analysis <Badge value={latestJob.status} /></h2>
          {stats && (
            <div className="grid">
              {[['Parsed', stats.parsed], ['Malformed', stats.malformed], ['Stored', stats.stored_events]].map(([l, v]) => (
                <div key={l} className="card stat"><div className="n">{v}</div><div className="l">{l}</div></div>
              ))}
            </div>
          )}
          {alerts.length > 0 && (
            <>
              <h3>Indicators (require human review)</h3>
              {alerts.map((a, i) => (
                <div key={i} className="note"><strong>{a.rule}</strong>: {a.text}</div>
              ))}
            </>
          )}
          {latestJob.result?.note && <p className="muted" style={{ marginTop: 8 }}>{latestJob.result.note}</p>}
        </div>
      )}

      {can('analysis:run') && (
        <div className="card">
          <h2>AI Network Intrusion Detection</h2>
          <p className="muted" style={{ marginBottom: 12 }}>
            Powered by a Random Forest model trained on 125,973 real network connections (NSL-KDD dataset).
            Classifies traffic as Normal or Attack with confidence scores.
          </p>
          <button className="btn primary" onClick={runMlScan} disabled={mlRunning}>
            {mlRunning ? 'Scanning…' : 'Run AI Intrusion Scan (Demo)'}
          </button>
          {mlResult && (
            <>
              <div className="grid" style={{ marginTop: 16 }}>
                {[
                  ['Connections Analysed', mlResult.total_connections],
                  ['Attacks Detected', mlResult.attacks_detected],
                  ['Normal Traffic', mlResult.normal_detected],
                ].map(([l, v]) => (
                  <div key={l} className="card stat">
                    <div className="n" style={{ color: l === 'Attacks Detected' && v > 0 ? 'var(--danger, #c0392b)' : undefined }}>{v}</div>
                    <div className="l">{l}</div>
                  </div>
                ))}
              </div>
              <p className="muted" style={{ marginTop: 8, fontSize: 12 }}>{mlResult.model_type}</p>
              <Table
                cols={[
                  { label: '#',           render: r => r.id },
                  { label: 'Connection',  render: r => r.description },
                  { label: 'Protocol',    render: r => r.protocol.toUpperCase() },
                  { label: 'Service',     render: r => r.service },
                  { label: 'Result',      render: r => (
                    <span style={{ fontWeight: 600, color: r.prediction === 'Attack' ? '#c0392b' : '#27ae60' }}>
                      {r.prediction}
                    </span>
                  )},
                  { label: 'Confidence',  render: r => r.confidence + '%' },
                ]}
                rows={mlResult.results}
              />
            </>
          )}
        </div>
      )}

      {selected && (
        <div className="card">
          <h2>Events</h2>
          <div className="row" style={{ marginBottom: 8 }}>
            <input placeholder="Search message" value={q} onChange={e => { setQ(e.target.value); setPage(1) }} />
            <input placeholder="Event type" value={etype} onChange={e => { setEtype(e.target.value); setPage(1) }} />
            <input placeholder="Source" value={source} onChange={e => { setSource(e.target.value); setPage(1) }} />
          </div>
          <Table
            cols={[
              { label: '#', render: r => r.line_no },
              { label: 'UTC time', render: r => r.ts_utc ? fmt(r.ts_utc) : '—' },
              { label: 'Type', render: r => r.event_type || '—' },
              { label: 'Source', render: r => r.source || '—' },
              { label: 'User', render: r => r.username || '—' },
              { label: 'Message', render: r => <span style={{ fontSize: 12 }}>{r.message}</span> },
            ]}
            rows={events} empty="No events. Run log analysis first." />
          <Pager page={page} size={SIZE} total={total} onChange={p => setPage(p)} />
        </div>
      )}
    </>
  )
}
