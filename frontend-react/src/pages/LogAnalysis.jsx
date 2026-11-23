import { useState, useEffect, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { api, fmt, qs, download } from '../api'
import { useAuth } from '../context/AuthContext'
import { useToast } from '../context/ToastContext'
import Badge from '../components/Badge'
import Table from '../components/Table'
import Pager from '../components/Pager'
import Bars from '../components/Bars'

const LOG_EXT = ['.log', '.txt', '.json', '.jsonl', '.csv']
const EVENT_TYPES = ['auth_failure', 'auth_success', 'privilege', 'general']

const isLogCandidate = e =>
  ['system_log', 'text'].includes(e.evidence_type) ||
  LOG_EXT.some(x => (e.original_filename || '').toLowerCase().endsWith(x)) ||
  /text|json|csv/.test(e.mime || '')

const isCsv = name => (name || '').toLowerCase().endsWith('.csv')

/* Activity-over-time chart: total events with authentication failures overlaid. */
function ActivityChart({ data }) {
  if (!data?.length) return <div className="empty">No timestamped events</div>
  const W = 720, H = 170, P = { l: 34, r: 8, t: 10, b: 26 }
  const max = Math.max(1, ...data.map(d => d.total))
  const bw = (W - P.l - P.r) / data.length
  const y = v => H - P.b - (v / max) * (H - P.t - P.b)
  const label = s => s.slice(5, 16).replace('T', ' ')
  return (
    <div style={{ overflowX: 'auto' }}>
      <svg viewBox={`0 0 ${W} ${H}`} style={{ width: '100%', minWidth: 480, height: 'auto' }} role="img"
           aria-label="Events over time">
        {[0, 0.5, 1].map(f => (
          <g key={f}>
            <line x1={P.l} x2={W - P.r} y1={y(max * f)} y2={y(max * f)} stroke="var(--line)" />
            <text x={P.l - 6} y={y(max * f) + 4} fontSize="10" fill="var(--muted)" textAnchor="end">
              {Math.round(max * f)}
            </text>
          </g>
        ))}
        {data.map((d, i) => (
          <g key={i}>
            <title>{`${fmt(d.start)} — ${d.total} event(s), ${d.failures} auth failure(s)`}</title>
            <rect x={P.l + i * bw + 1} y={y(d.total)} width={Math.max(bw - 2, 1)} height={H - P.b - y(d.total)}
                  rx="2" fill="var(--blue)" opacity=".75" />
            {d.failures > 0 && (
              <rect x={P.l + i * bw + 1} y={y(d.failures)} width={Math.max(bw - 2, 1)}
                    height={H - P.b - y(d.failures)} rx="2" fill="var(--red)" />
            )}
          </g>
        ))}
        {[0, Math.floor(data.length / 2), data.length - 1].map(i => (
          <text key={i} x={P.l + i * bw + bw / 2} y={H - 8} fontSize="10" fill="var(--muted)"
                textAnchor={i === 0 ? 'start' : i === data.length - 1 ? 'end' : 'middle'}>
            {label(data[i].start)}
          </text>
        ))}
      </svg>
      <div className="muted" style={{ fontSize: 12, display: 'flex', gap: 16, marginTop: 4 }}>
        <span><span style={{ color: 'var(--blue)' }}>■</span> All events</span>
        <span><span style={{ color: 'var(--red)' }}>■</span> Authentication failures</span>
      </div>
    </div>
  )
}

function LogSummary({ s }) {
  if (!s || !s.by_type?.length) return null
  return (
    <div className="card">
      <h2>Log overview</h2>
      <p className="muted" style={{ marginBottom: 12, fontSize: 13 }}>
        {s.first ? <>Activity from <b>{fmt(s.first)}</b> to <b>{fmt(s.last)}</b> (UTC)</> : 'No timestamped events'}
        {s.undated > 0 && <> · {s.undated} undated event(s)</>}
      </p>
      <h3>Events over time</h3>
      <ActivityChart data={s.timeline} />
      <div className="grid two" style={{ marginTop: 16 }}>
        <div><h3>Event types</h3><Bars data={s.by_type} /></div>
        <div><h3>Top users</h3><Bars data={s.top_users} empty="No usernames found" /></div>
        <div><h3>Top sources</h3><Bars data={s.top_sources} empty="No sources found" /></div>
        <div>
          <h3>Top IP addresses</h3>
          <Bars data={s.top_ips} empty="No IP addresses found" />
          {s.top_failed_ips?.length > 0 && (
            <div className="alert" style={{ marginTop: 10 }}>
              Most failed logins from <b>{s.top_failed_ips[0].label}</b> ({s.top_failed_ips[0].value} failure(s))
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function IntrusionResult({ r }) {
  const fromEvidence = r.source === 'evidence'
  const ev = r.evaluation
  const cols = fromEvidence
    ? [
        { label: 'Row', render: x => x.row },
        { label: 'Protocol', render: x => (x.protocol || '').toUpperCase() },
        { label: 'Service', render: x => x.service },
        { label: 'Flag', render: x => x.flag },
        { label: 'Bytes (src → dst)', render: x => `${x.src_bytes} → ${x.dst_bytes}` },
        ...(ev ? [{ label: 'Actual label', render: x => x.actual }] : []),
      ]
    : [
        { label: '#', render: x => x.id },
        { label: 'Connection', render: x => x.description },
        { label: 'Protocol', render: x => x.protocol.toUpperCase() },
        { label: 'Service', render: x => x.service },
      ]
  cols.push(
    { label: 'Result', render: x => (
      <span style={{ fontWeight: 600, color: x.prediction === 'Attack' ? 'var(--red)' : 'var(--green)' }}>
        {x.prediction}
      </span>
    )},
    { label: 'Confidence', render: x => x.confidence + '%' },
  )
  const tiles = [
    ['Connections Analysed', r.total_connections],
    ['Attacks Detected', r.attacks_detected],
    ['Normal Traffic', r.normal_detected],
    ...(ev ? [['Accuracy vs labels', ev.accuracy + '%']] : []),
  ]
  return (
    <>
      <div className="grid" style={{ marginTop: 16 }}>
        {tiles.map(([l, v]) => (
          <div key={l} className="card stat">
            <div className="n" style={{ color: l === 'Attacks Detected' && v > 0 ? 'var(--red)' : undefined }}>{v}</div>
            <div className="l">{l}</div>
          </div>
        ))}
      </div>
      <p className="muted" style={{ marginTop: 8, fontSize: 12 }}>
        {r.model_type}
        {fromEvidence ? '' : ' · Demo data (built-in sample connections, not case evidence)'}
        {r.skipped_rows > 0 && ` · ${r.skipped_rows} malformed row(s) skipped`}
        {r.row_limit_reached && ' · Row limit reached; only the first 100,000 rows were scanned'}
      </p>
      {ev && (
        <p className="muted" style={{ fontSize: 12 }}>
          True positives {ev.true_positive} · True negatives {ev.true_negative} ·
          False positives {ev.false_positive} · False negatives {ev.false_negative}
        </p>
      )}
      {fromEvidence && r.attacks_by_service?.length > 0 && (
        <div className="grid two" style={{ marginTop: 12 }}>
          <div><h3>Attacks by service</h3><Bars data={r.attacks_by_service} /></div>
          <div><h3>Attacks by protocol</h3><Bars data={r.attacks_by_protocol} /></div>
        </div>
      )}
      {r.results_truncated && (
        <p className="muted" style={{ fontSize: 12, marginTop: 8 }}>
          Showing the first 500 results (attacks first, highest confidence first).
        </p>
      )}
      <Table cols={cols} rows={r.results} />
      {r.note && <p className="muted" style={{ marginTop: 8, fontSize: 12 }}>{r.note}</p>}
    </>
  )
}

export default function LogAnalysis() {
  const { can } = useAuth()
  const toast = useToast()
  const [cases, setCases] = useState([])
  const [caseId, setCaseId] = useState('')
  const [evidence, setEvidence] = useState([])
  const [evLoaded, setEvLoaded] = useState(false)
  const [selected, setSelected] = useState(null)
  const [jobs, setJobs] = useState([])
  const [summary, setSummary] = useState(null)
  const [running, setRunning] = useState(false)
  const [events, setEvents] = useState([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [q, setQ] = useState('')
  const [etype, setEtype] = useState('')
  const [source, setSource] = useState('')
  const [mlRunning, setMlRunning] = useState(false)
  const [mlResult, setMlResult] = useState(null)
  const [mlError, setMlError] = useState('')
  const SIZE = 25

  useEffect(() => { api('/cases?size=100').then(r => setCases(r.items)).catch(() => {}) }, [])

  const loadEvidence = useCallback(async () => {
    setEvLoaded(false)
    if (!caseId) { setEvidence([]); return }
    try {
      const r = await api('/evidence?' + qs({ case_id: caseId, size: 100 }))
      setEvidence(r.items.filter(isLogCandidate))
    } catch (err) { toast(err.message, true) }
    finally { setEvLoaded(true) }
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

  const loadSummary = id => api('/log-analysis/' + id + '/stats').then(setSummary).catch(() => setSummary(null))

  const selectEvidence = async id => {
    setSelected(id || null); setPage(1); setQ(''); setEtype(''); setSource('')
    setJobs([]); setSummary(null); setMlResult(null); setMlError('')
    if (!id) return
    try { setJobs(await api('/log-analysis/' + id + '/summary')) } catch { setJobs([]) }
    loadSummary(id)
    try {
      const j = await api('/ml/intrusion-detect/' + id + '/latest')
      if (j?.status === 'completed') setMlResult(j.result)
    } catch { /* no previous scan */ }
  }

  const runLog = async () => {
    if (!selected) return
    setRunning(true)
    try {
      const job = await api('/log-analysis/' + selected, { method: 'POST' })
      if (job.status === 'failed') toast(job.error || 'Log analysis failed', true)
      else toast('Log analysis complete')
      setJobs(await api('/log-analysis/' + selected + '/summary'))
      loadSummary(selected); loadEvents()
    } catch (err) { toast(err.message, true) }
    finally { setRunning(false) }
  }

  const runMlScan = async onEvidence => {
    setMlRunning(true); setMlResult(null); setMlError('')
    try {
      if (onEvidence) {
        const job = await api('/ml/intrusion-detect/' + selected, { method: 'POST' })
        if (job.status !== 'completed') { setMlError(job.error || 'Scan failed'); toast('AI scan failed', true); return }
        setMlResult(job.result)
        toast('AI scan complete — ' + job.result.attacks_detected + ' attack(s) detected')
      } else {
        const r = await api('/ml/intrusion-detect', { method: 'POST' })
        setMlResult(r)
        toast('Demo scan complete — ' + r.attacks_detected + ' attack(s) detected')
      }
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
  const selectedEv = evidence.find(e => e.id === selected)

  return (
    <>
      <h1>Log Analysis</h1>
      <p className="muted">
        Parse a case's log files into searchable events, see activity at a glance, and flag suspicious behaviour for review.
      </p>
      <div className="row">
        <select value={caseId} onChange={e => { setCaseId(e.target.value); selectEvidence('') }}>
          <option value="">Select a case…</option>
          {cases.map(c => <option key={c.id} value={c.id}>{c.ref} — {c.title}</option>)}
        </select>
        {caseId && evidence.length > 0 && (
          <select value={selected || ''} onChange={e => selectEvidence(e.target.value)}>
            <option value="">Select evidence…</option>
            {evidence.map(e => <option key={e.id} value={e.id}>{e.ref} — {e.original_filename}</option>)}
          </select>
        )}
        <span className="spacer" />
        {selected && can('analysis:run') && !isCsv(selectedEv?.original_filename) && (
          <button className="btn primary" onClick={runLog} disabled={running}>{running ? 'Parsing…' : 'Parse log'}</button>
        )}
        {selected && latestJob && <button className="btn" onClick={exportCsv}>Export CSV</button>}
      </div>

      {!caseId && (
        <div className="note">Select a case to list its log files.</div>
      )}
      {caseId && evLoaded && evidence.length === 0 && (
        <div className="note">
          This case has no log files yet. Upload a <b>.log</b>, <b>.txt</b>, <b>.json/.jsonl</b> or network
          <b> .csv</b> file as <b>System Log</b> evidence in <Link to="/evidence">Digital Evidence</Link>, then come back here.
        </div>
      )}
      {selected && !latestJob && !isCsv(selectedEv?.original_filename) && (
        <div className="note">This log has not been parsed yet. Click <b>Parse log</b> to analyse it.</div>
      )}

      {latestJob && (
        <div className="card">
          <h2>Latest analysis <Badge value={latestJob.status} /></h2>
          {latestJob.error && <p className="error">{latestJob.error}</p>}
          {stats && (
            <div className="grid">
              {[['Parsed', stats.parsed], ['Malformed', stats.malformed], ['Stored', stats.stored_events], ['Indicators', alerts.length]].map(([l, v]) => (
                <div key={l} className="card stat"><div className="n">{v}</div><div className="l">{l}</div></div>
              ))}
            </div>
          )}
          {alerts.length > 0 && (
            <>
              <h3>Indicators (require human review)</h3>
              {alerts.map((a, i) => (
                <div key={i} className="alert"><strong>{a.rule.replace(/_/g, ' ')}</strong>: {a.text}</div>
              ))}
            </>
          )}
          {latestJob.result?.note && <p className="muted" style={{ marginTop: 8 }}>{latestJob.result.note}</p>}
        </div>
      )}

      {latestJob?.status === 'completed' && <LogSummary s={summary} />}

      {can('analysis:run') && (
        <div className="card">
          <h2>AI Network Intrusion Detection</h2>
          <p className="muted" style={{ marginBottom: 12 }}>
            A Random Forest model trained on 125,973 real network connections (NSL-KDD dataset) classifies each
            connection as Normal or Attack. Select a network-connections <b>.csv</b> evidence file to scan it, or run
            the demo on built-in sample traffic.
          </p>
          <div className="row">
            <button className="btn primary" onClick={() => runMlScan(true)}
                    disabled={mlRunning || !selected || !isCsv(selectedEv?.original_filename)}
                    title={!isCsv(selectedEv?.original_filename) ? 'Select a .csv evidence file first' : ''}>
              {mlRunning ? 'Scanning…' : 'Scan selected evidence'}
            </button>
            <button className="btn" onClick={() => runMlScan(false)} disabled={mlRunning}>Run demo scan</button>
          </div>
          {mlError && <p className="error" style={{ marginTop: 12 }}>{mlError}</p>}
          {mlResult && <IntrusionResult r={mlResult} />}
        </div>
      )}

      {selected && latestJob && (
        <div className="card">
          <h2>Events</h2>
          <div className="row" style={{ marginBottom: 8 }}>
            <input placeholder="Search message" value={q} onChange={e => { setQ(e.target.value); setPage(1) }} />
            <select value={etype} onChange={e => { setEtype(e.target.value); setPage(1) }}>
              <option value="">All event types</option>
              {EVENT_TYPES.map(t => <option key={t} value={t}>{t.replace('_', ' ')}</option>)}
            </select>
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
            rows={events} empty="No events match the filters." />
          <Pager page={page} size={SIZE} total={total} onChange={p => setPage(p)} />
        </div>
      )}
    </>
  )
}
