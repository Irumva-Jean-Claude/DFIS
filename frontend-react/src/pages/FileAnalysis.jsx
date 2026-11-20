import { useState, useEffect, useCallback } from 'react'
import { api, fmt, qs } from '../api'
import { useAuth } from '../context/AuthContext'
import { useToast } from '../context/ToastContext'
import Badge from '../components/Badge'
import Table from '../components/Table'
import Modal from '../components/Modal'
import KeyValue from '../components/KeyValue'

function SearchResults({ results }) {
  if (!results) return null
  if (!results.supported) return <p className="muted">This file type is not supported for keyword search (plain text, PDF and DOCX only).</p>
  const { stats, matches } = results
  return (
    <>
      <p className="muted">Searched {stats?.lines_searched ?? '?'} lines — {stats?.total_matches ?? 0} matches.</p>
      {matches?.length > 0 ? (
        <Table
          cols={[
            { label: 'Line', render: r => r.line_no },
            { label: 'Keywords', render: r => <>{r.matched_keywords.map(k => <Badge key={k} value={k} />)}</> },
            { label: 'Context', render: r => <code style={{ fontSize: 11 }}>{r.context}</code> },
          ]}
          rows={matches}
          empty="No matches." />
      ) : <p className="muted">No matches found.</p>}
    </>
  )
}

function AnalysisDetail({ job }) {
  if (!job?.result) return null
  const r = job.result
  const obs = r.observations || {}
  return (
    <>
      <h3>Observations</h3>
      <KeyValue data={{
        'Detected type': obs.detected_type, 'MIME': obs.detected_mime,
        'Size': obs.size_bytes, 'Encoding': obs.encoding,
        'Hash match': String(obs.reference_hash_matches_working_copy),
      }} />
      {r.interpretations?.length > 0 && (
        <><h3>Interpretations</h3>
        {r.interpretations.map((i, n) => <p key={n} className="muted">{i}</p>)}</>
      )}
      {r.warnings?.length > 0 && (
        <><h3>Warnings</h3>
        {r.warnings.map((w, n) => <p key={n} className="error">{w}</p>)}</>
      )}
    </>
  )
}

export default function FileAnalysis() {
  const { can } = useAuth()
  const toast = useToast()
  const [evidence, setEvidence] = useState([])
  const [caseId, setCaseId] = useState('')
  const [cases, setCases] = useState([])
  const [selected, setSelected] = useState(null)
  const [jobs, setJobs] = useState([])
  const [running, setRunning] = useState(false)
  const [kw, setKw] = useState('')
  const [searching, setSearching] = useState(false)
  const [searchResults, setSearchResults] = useState(null)

  useEffect(() => {
    api('/cases?size=100').then(r => setCases(r.items)).catch(() => {})
  }, [])

  const loadEvidence = useCallback(async () => {
    try {
      const r = await api('/evidence?' + qs({ case_id: caseId, size: 100 }))
      setEvidence(r.items)
    } catch (err) { toast(err.message, true) }
  }, [caseId])

  useEffect(() => { loadEvidence() }, [loadEvidence])

  const loadJobs = useCallback(async id => {
    try {
      const h = await api('/file-analysis/' + id)
      setJobs(h)
    } catch (err) { toast(err.message, true) }
  }, [])

  const selectEvidence = id => {
    setSelected(id); setSearchResults(null); setKw('')
    loadJobs(id)
  }

  const runAnalysis = async () => {
    if (!selected) return
    setRunning(true)
    try {
      await api('/file-analysis/' + selected, { method: 'POST' })
      toast('Analysis complete'); loadJobs(selected)
    } catch (err) { toast(err.message, true) }
    finally { setRunning(false) }
  }

  const runSearch = async () => {
    if (!selected || !kw.trim()) return
    const keywords = kw.split(',').map(k => k.trim()).filter(Boolean)
    if (!keywords.length) { toast('Enter at least one keyword', true); return }
    setSearching(true); setSearchResults(null)
    try {
      const r = await api('/file-analysis/' + selected + '/search', { method: 'POST', body: { keywords } })
      setSearchResults(r)
    } catch (err) { toast(err.message, true) }
    finally { setSearching(false) }
  }

  const selectedItem = evidence.find(e => e.id === selected)

  return (
    <>
      <h1>File Analysis</h1>
      <div className="row">
        <select value={caseId} onChange={e => { setCaseId(e.target.value); setSelected(null); setJobs([]) }}>
          <option value="">All cases</option>
          {cases.map(c => <option key={c.id} value={c.id}>{c.ref} — {c.title}</option>)}
        </select>
        <span className="spacer" />
      </div>

      <div className="grid two">
        <div className="card">
          <h2>Evidence</h2>
          <Table
            cols={[
              { label: 'Ref', render: r => <a href="#" onClick={e => { e.preventDefault(); selectEvidence(r.id) }}>{r.ref}</a> },
              { label: 'File', render: r => r.original_filename },
              { label: 'Type', render: r => <Badge value={r.evidence_type} /> },
            ]}
            rows={evidence} empty="No evidence items." />
        </div>

        <div className="card">
          <h2>{selectedItem ? `${selectedItem.ref} — ${selectedItem.original_filename}` : 'Select evidence'}</h2>
          {selected && (
            <>
              {can('analysis:run') && (
                <button className="btn primary sm" onClick={runAnalysis} disabled={running} style={{ marginBottom: 8 }}>
                  {running ? 'Running…' : 'Run file analysis'}
                </button>
              )}
              <h3>Analysis history</h3>
              <Table
                cols={[
                  { label: 'Status', render: j => <Badge value={j.status} /> },
                  { label: 'By', render: j => j.by_user },
                  { label: 'Time', render: j => fmt(j.created_at) },
                ]}
                rows={jobs} empty="No analysis run yet." />
              {jobs[0]?.status === 'completed' && <AnalysisDetail job={jobs[0]} />}
            </>
          )}
        </div>
      </div>

      {selected && can('analysis:run') && (
        <div className="card">
          <h2>Keyword Search</h2>
          <p className="muted">Search for keywords within the file content. Supports plain text, PDF, and DOCX files.</p>
          <div className="row">
            <input
              placeholder="e.g. password, login, error (comma-separated)"
              value={kw}
              onChange={e => setKw(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && runSearch()}
              style={{ flex: 1 }}
            />
            <button className="btn primary sm" onClick={runSearch} disabled={searching || !kw.trim()}>
              {searching ? 'Searching…' : 'Search'}
            </button>
          </div>
          <SearchResults results={searchResults} />
        </div>
      )}
    </>
  )
}
