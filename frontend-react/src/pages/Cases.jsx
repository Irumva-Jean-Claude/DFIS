import { useState, useEffect, useCallback } from 'react'
import { useLocation } from 'react-router-dom'
import { api, fmt, qs } from '../api'
import { useAuth } from '../context/AuthContext'
import { useToast } from '../context/ToastContext'
import Badge from '../components/Badge'
import Table from '../components/Table'
import Pager from '../components/Pager'
import Modal from '../components/Modal'
import KeyValue from '../components/KeyValue'

function CaseDetail({ id, onClose, onRefresh }) {
  const { can } = useAuth()
  const toast = useToast()
  const [c, setC] = useState(null)
  const [hist, setHist] = useState([])
  const [dir, setDir] = useState([])

  useEffect(() => {
    Promise.all([
      api('/cases/' + id),
      api('/cases/' + id + '/history'),
      can('case:assign') ? api('/users/directory') : Promise.resolve([]),
    ]).then(([c, h, d]) => { setC(c); setHist(h); setDir(d) })
  }, [id])

  if (!c) return <Modal title="Loading…" onClose={onClose}><p className="muted">Loading…</p></Modal>

  const nexts = { open: ['active', 'closed'], active: ['closed'], closed: ['active', 'archived'], archived: [] }[c.status] || []

  const changeStatus = async s => {
    if (!confirm(`Change status to "${s}"?`)) return
    try { await api('/cases/' + id, { method: 'PATCH', body: { status: s } }); toast('Status updated'); onRefresh(); onClose() }
    catch (e) { toast(e.message, true) }
  }

  const assign = async e => {
    e.preventDefault()
    const uid = e.target.assignee.value
    try { await api('/cases/' + id + '/assign', { method: 'POST', body: { user_id: uid } }); toast('Investigator assigned'); onRefresh(); onClose() }
    catch (e) { toast(e.message, true) }
  }

  return (
    <Modal title={`${c.ref} — ${c.title}`} onClose={onClose} wide>
      <div className="row"><Badge value={c.status} /> <Badge value={c.priority} /></div>
      <KeyValue data={{ Description: c.description, Category: c.category, Created: fmt(c.created_at), Investigators: c.investigators.map(i => i.name).join(', '), 'Retention until': fmt(c.retention_until) }} />

      {can('case:edit') && nexts.length > 0 && (
        <><h3>Change status</h3>
        <div className="row">{nexts.map(s => <button key={s} type="button" className="btn sm" onClick={() => changeStatus(s)}>{s}</button>)}</div></>
      )}

      {can('case:assign') && dir.length > 0 && (
        <><h3>Assign investigator</h3>
        <form onSubmit={assign}>
          <div className="row">
            <select name="assignee">{dir.map(u => <option key={u.id} value={u.id}>{u.full_name} ({u.role})</option>)}</select>
            <button className="btn sm" type="submit">Assign</button>
          </div>
        </form></>
      )}

      <h3>Case history</h3>
      <Table cols={[{ label: 'Time', render: r => fmt(r.ts) }, { label: 'Actor', render: r => r.actor }, { label: 'Action', render: r => r.action }]} rows={hist} empty="No history." />
    </Modal>
  )
}

export default function Cases() {
  const { can } = useAuth()
  const toast = useToast()
  const loc = useLocation()
  const [items, setItems] = useState([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [q, setQ] = useState(() => new URLSearchParams(loc.search).get('q') || '')
  const [status, setStatus] = useState('')
  const [priority, setPriority] = useState('')
  const [sort, setSort] = useState('created_at')
  const [selected, setSelected] = useState(null)
  const [creating, setCreating] = useState(false)
  const SIZE = 10

  const load = useCallback(async () => {
    try {
      const r = await api('/cases?' + qs({ q, status, priority, sort, order: sort === 'created_at' ? 'desc' : 'asc', page, size: SIZE }))
      setItems(r.items); setTotal(r.total)
    } catch (e) { toast(e.message, true) }
  }, [q, status, priority, sort, page])

  useEffect(() => { load() }, [load])

  const create = async e => {
    e.preventDefault()
    const fd = new FormData(e.target)
    try { await api('/cases', { method: 'POST', body: Object.fromEntries(fd) }); toast('Case created'); setCreating(false); load() }
    catch (e) { toast(e.message, true) }
  }

  return (
    <>
      <h1>Investigation Cases</h1>
      <div className="row">
        <input placeholder="Search title or reference" value={q} onChange={e => { setQ(e.target.value); setPage(1) }} />
        <select value={status} onChange={e => { setStatus(e.target.value); setPage(1) }}>
          <option value="">All statuses</option>
          {['open', 'active', 'closed', 'archived'].map(s => <option key={s}>{s}</option>)}
        </select>
        <select value={priority} onChange={e => { setPriority(e.target.value); setPage(1) }}>
          <option value="">All priorities</option>
          {['low', 'medium', 'high', 'critical'].map(s => <option key={s}>{s}</option>)}
        </select>
        <select value={sort} onChange={e => setSort(e.target.value)}>
          <option value="created_at">Newest</option>
          <option value="title">Title</option>
          <option value="priority">Priority</option>
        </select>
        <span className="spacer" />
        {can('case:create') && <button className="btn primary" onClick={() => setCreating(true)}>New case</button>}
      </div>

      <div className="card">
        <Table
          cols={[
            { label: 'Ref', render: c => <a href="#" onClick={e => { e.preventDefault(); setSelected(c.id) }}>{c.ref}</a> },
            { label: 'Title', render: c => c.title },
            { label: 'Priority', render: c => <Badge value={c.priority} /> },
            { label: 'Status', render: c => <Badge value={c.status} /> },
            { label: 'Evidence', render: c => c.evidence_count },
            { label: 'Created', render: c => fmt(c.created_at) },
          ]}
          rows={items}
          empty="No cases match. Create one to begin."
        />
        <Pager page={page} size={SIZE} total={total} onChange={p => setPage(p)} />
      </div>

      {selected && <CaseDetail id={selected} onClose={() => setSelected(null)} onRefresh={load} />}

      {creating && (
        <Modal title="New case" onClose={() => setCreating(false)}>
          <form onSubmit={create}>
            <label>Title<input name="title" required /></label>
            <label>Description<textarea name="description" rows={3} /></label>
            <label>Category<input name="category" defaultValue="general" /></label>
            <label>Priority
              <select name="priority">
                {['low', 'medium', 'high', 'critical'].map(p => <option key={p}>{p}</option>)}
              </select>
            </label>
            <button className="btn primary">Create</button>
          </form>
        </Modal>
      )}
    </>
  )
}
