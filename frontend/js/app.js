'use strict';
const $ = (s, r = document) => r.querySelector(s);
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmt = d => d ? esc(String(d).replace('T', ' ').replace('Z', ' UTC')) : '-';
const badge = t => `<span class="badge b-${esc(String(t).toLowerCase())}">${esc(t)}</span>`;
let TOKEN = sessionStorage.getItem('dfis_t'), ME = null;
const can = p => ME && ME.permissions.includes(p);

async function api(path, { method = 'GET', body, form, raw } = {}) {
  const h = {}; if (TOKEN) h.Authorization = 'Bearer ' + TOKEN;
  let b; if (form) b = form; else if (body !== undefined) { h['Content-Type'] = 'application/json'; b = JSON.stringify(body); }
  const r = await fetch('/api/v1' + path, { method, headers: h, body: b });
  if (r.status === 401 && !path.startsWith('/auth/login')) { logout(true); throw new Error('Session expired - please sign in again'); }
  if (!r.ok) { let m = r.statusText; try { const j = await r.json(); m = typeof j.detail === 'string' ? j.detail : j.detail.map(x => (x.loc || []).slice(-1) + ': ' + x.msg).join('; '); } catch { } throw new Error(m); }
  return raw ? r : r.json();
}
async function download(path, name) {
  const r = await api(path, { raw: true }), a = document.createElement('a');
  a.href = URL.createObjectURL(await r.blob()); a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}
function toast(msg, err) { const t = document.createElement('div'); t.className = 'toast' + (err ? ' err' : ''); t.textContent = msg; $('#toasts').appendChild(t); setTimeout(() => t.remove(), 4500); }
const guard = fn => async (...a) => { try { return await fn(...a); } catch (e) { toast(e.message, true); } };
const qs = o => Object.entries(o).filter(([, v]) => v !== '' && v != null).map(([k, v]) => k + '=' + encodeURIComponent(v)).join('&');

function modal(title, html, onSubmit, wide) {
  const bg = document.createElement('div'); bg.className = 'modal-bg';
  bg.innerHTML = `<form class="modal ${wide ? 'wide' : ''}" role="dialog" aria-modal="true"><h2><span>${esc(title)}</span><button type="button" class="btn sm ghost" data-x aria-label="Close">&times;</button></h2>${html}</form>`;
  document.body.appendChild(bg);
  const close = () => bg.remove(); bg.querySelector('[data-x]').onclick = close;
  bg.addEventListener('keydown', e => { if (e.key === 'Escape') close(); });
  const f = bg.querySelector('form'); const first = f.querySelector('input,select,textarea'); if (first) first.focus();
  f.onsubmit = guard(async e => { e.preventDefault(); if (onSubmit && await onSubmit(f, new FormData(f), close) !== false) close(); });
  return { bg, f, close };
}
const field = (label, name, o = {}) => `<label>${esc(label)}${o.type === 'select' ? `<select name="${name}" ${o.req ? 'required' : ''}>${o.opts.map(x => Array.isArray(x) ? `<option value="${esc(x[0])}">${esc(x[1])}</option>` : `<option>${esc(x)}</option>`).join('')}</select>` : o.type === 'textarea' ? `<textarea name="${name}" rows="3" ${o.req ? 'required' : ''}></textarea>` : `<input name="${name}" type="${o.type || 'text'}" ${o.req ? 'required' : ''} ${o.accept ? 'accept="' + o.accept + '"' : ''} ${o.value ? 'value="' + esc(o.value) + '"' : ''}>`}</label>`;
const table = (cols, rows, empty = 'No records yet.') => rows.length ? `<div class="tablewrap"><table><thead><tr>${cols.map(c => `<th>${esc(c[0])}</th>`).join('')}</tr></thead><tbody>${rows.map(r => `<tr>${cols.map(c => `<td>${c[1](r)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>` : `<div class="empty">${esc(empty)}</div>`;
const bars = (data, empty = 'No data yet') => { const m = Math.max(1, ...data.map(d => d.value)); return data.length ? `<div class="bars">${data.map(d => `<div class="r"><span>${esc(d.label)}</span><div class="bar"><i style="width:${d.value / m * 100}%"></i></div><b>${d.value}</b></div>`).join('')}</div>` : `<div class="empty">${empty}</div>`; };
const kv = o => `<dl class="kv">${Object.entries(o).filter(([, v]) => v != null && v !== '').map(([k, v]) => `<dt>${esc(k)}</dt><dd>${typeof v === 'object' ? `<pre>${esc(JSON.stringify(v, null, 2))}</pre>` : esc(v)}</dd>`).join('')}</dl>`;
function pager(el, st, total, reload) {
  const pages = Math.max(1, Math.ceil(total / st.size));
  el.innerHTML = `<span class="muted">${total} record(s) - page ${st.page}/${pages}</span><button class="btn sm" ${st.page <= 1 ? 'disabled' : ''} data-p="-1">Prev</button><button class="btn sm" ${st.page >= pages ? 'disabled' : ''} data-p="1">Next</button>`;
  el.querySelectorAll('[data-p]').forEach(b => b.onclick = () => { st.page += +b.dataset.p; reload(); });
}
async function evOptions(caseId) { const r = await api('/evidence?' + qs({ size: 200, case_id: caseId })); return r.items; }
const evSel = (items, id = 'ev') => `<select id="${id}" aria-label="Evidence">${items.length ? items.map(e => `<option value="${e.id}">${esc(e.ref)} - ${esc(e.original_filename)}</option>`).join('') : '<option value="">(no evidence)</option>'}</select>`;

// ---------------- pages ----------------
const pages = {};
pages.dashboard = async v => {
  const d = await api('/dashboard');
  v.innerHTML = `<h1>Dashboard</h1><p class="muted">Live metrics from the backend for the cases you can access.</p>
  <div class="grid">${[['Total cases', d.cases.total], ['Open', d.cases.open], ['Active', d.cases.active], ['Closed', d.cases.closed], ['Evidence items', d.evidence_total]].map(x => `<div class="card stat"><div class="n">${x[1]}</div><div class="l">${x[0]}</div></div>`).join('')}</div>
  <div class="grid two"><div class="card"><h2>Evidence by type</h2>${bars(d.evidence_by_type)}</div><div class="card"><h2>Analysis jobs</h2>${bars(d.analysis, 'No analysis run yet')}</div></div>
  <div class="card"><h2>Activity (last 14 days)</h2>${bars(d.activity)}</div>
  <div class="grid two"><div class="card"><h2>Recent integrity checks</h2>${table([['Evidence', r => esc(r.evidence)], ['Result', r => badge(r.result)], ['Time', r => fmt(r.at)]], d.recent_integrity, 'No integrity checks yet.')}</div>
  <div class="card"><h2>Pending custody actions</h2>${table([['Evidence', r => esc(r.evidence)], ['Since', r => fmt(r.at)]], d.pending_custody, 'Nothing awaiting acknowledgment.')}</div></div>
  <div class="card"><h2>Recent audit events</h2>${table([['Time', r => fmt(r.ts)], ['Actor', r => esc(r.actor || '-')], ['Action', r => esc(r.action)], ['Outcome', r => badge(r.outcome)]], d.recent_audit, 'No audit events visible.')}</div>`;
};

pages.cases = async v => {
  const st = { page: 1, size: 10 };
  v.innerHTML = `<h1>Investigation Cases</h1><div class="row"><input id="q" placeholder="Search title or reference" aria-label="Search"><select id="fs" aria-label="Status"><option value="">All statuses</option>${['open', 'active', 'closed', 'archived'].map(s => `<option>${s}</option>`).join('')}</select><select id="fp" aria-label="Priority"><option value="">All priorities</option>${['low', 'medium', 'high', 'critical'].map(s => `<option>${s}</option>`).join('')}</select><select id="so" aria-label="Sort"><option value="created_at">Newest</option><option value="title">Title</option><option value="priority">Priority</option></select><span class="spacer"></span>${can('case:create') ? '<button class="btn primary" id="new">New case</button>' : ''}</div><div class="card"><div id="list"></div><div class="pager" id="pg"></div></div>`;
  const load = guard(async () => {
    const r = await api('/cases?' + qs({ q: $('#q').value, status: $('#fs').value, priority: $('#fp').value, sort: $('#so').value, order: $('#so').value === 'created_at' ? 'desc' : 'asc', page: st.page, size: st.size }));
    $('#list').innerHTML = table([['Ref', c => `<a href="#" data-c="${c.id}">${esc(c.ref)}</a>`], ['Title', c => esc(c.title)], ['Priority', c => badge(c.priority)], ['Status', c => badge(c.status)], ['Evidence', c => c.evidence_count], ['Created', c => fmt(c.created_at)]], r.items, 'No cases match. Create one to begin.');
    $('#list').querySelectorAll('[data-c]').forEach(a => a.onclick = e => { e.preventDefault(); caseDetail(a.dataset.c, load); });
    pager($('#pg'), st, r.total, load);
  });
  ['q', 'fs', 'fp', 'so'].forEach(i => $('#' + i).onchange = () => { st.page = 1; load(); });
  if ($('#new')) $('#new').onclick = () => modal('New case', field('Title', 'title', { req: 1 }) + field('Description', 'description', { type: 'textarea' }) + field('Category', 'category', { value: 'general' }) + field('Priority', 'priority', { type: 'select', opts: ['low', 'medium', 'high', 'critical'] }) + '<button class="btn primary">Create</button>', async (f, fd) => { await api('/cases', { method: 'POST', body: Object.fromEntries(fd) }); toast('Case created'); load(); });
  load();
};
async function caseDetail(id, after) {
  const c = await api('/cases/' + id), hist = await api(`/cases/${id}/history`), dir = can('case:assign') ? await api('/users/directory') : [];
  const nexts = { open: ['active', 'closed'], active: ['closed'], closed: ['active', 'archived'], archived: [] }[c.status];
  const m = modal(c.ref + ' - ' + c.title, `<div class="row">${badge(c.status)} ${badge(c.priority)}</div>${kv({ Description: c.description, Category: c.category, Created: fmt(c.created_at), Investigators: c.investigators.map(i => i.name).join(', '), 'Retention until': fmt(c.retention_until) })}
  ${can('case:edit') && nexts.length ? `<h3>Change status</h3><div class="row">${nexts.map(s => `<button type="button" class="btn sm" data-s="${s}">${s}</button>`).join('')}</div>` : ''}
  ${can('case:assign') ? `<h3>Assign investigator</h3><div class="row"><select id="as">${dir.map(u => `<option value="${u.id}">${esc(u.full_name)} (${esc(u.role)})</option>`).join('')}</select><button type="button" class="btn sm" id="asb">Assign</button></div>` : ''}
  <h3>Case history</h3>${table([['Time', h => fmt(h.ts)], ['Actor', h => esc(h.actor)], ['Action', h => esc(h.action)]], hist, 'No history.')}`, null, true);
  m.bg.querySelectorAll('[data-s]').forEach(b => b.onclick = guard(async () => { if (!confirm(`Change status to "${b.dataset.s}"?`)) return; await api('/cases/' + id, { method: 'PATCH', body: { status: b.dataset.s } }); m.close(); toast('Status updated'); after(); }));
  const ab = m.bg.querySelector('#asb'); if (ab) ab.onclick = guard(async () => { await api(`/cases/${id}/assign`, { method: 'POST', body: { user_id: m.bg.querySelector('#as').value } }); m.close(); toast('Investigator assigned'); after(); });
}

pages.evidence = async v => {
  const st = { page: 1, size: 10 }, cs = (await api('/cases?size=100')).items;
  v.innerHTML = `<h1>Digital Evidence</h1><div class="row"><input id="q" placeholder="Search ref, filename or hash prefix" aria-label="Search"><select id="fc" aria-label="Case"><option value="">All cases</option>${cs.map(c => `<option value="${c.id}">${esc(c.ref)}</option>`).join('')}</select><span class="spacer"></span><button class="btn" id="exp">Export CSV</button>${can('evidence:upload') ? '<button class="btn primary" id="up">Register evidence</button>' : ''}</div><div class="card"><div id="list"></div><div class="pager" id="pg"></div></div>`;
  const load = guard(async () => {
    const r = await api('/evidence?' + qs({ q: $('#q').value, case_id: $('#fc').value, page: st.page, size: st.size }));
    $('#list').innerHTML = table([['Ref', e => `<a href="#" data-e="${e.id}">${esc(e.ref)}</a>`], ['File', e => esc(e.original_filename)], ['Case', e => esc(e.case_ref)], ['Type', e => esc(e.evidence_type)], ['Size', e => e.size + ' B'], ['SHA-256', e => `<code>${esc(e.sha256.slice(0, 16))}&hellip;</code>`], ['Status', e => badge(e.status)]], r.items, 'No evidence registered yet.');
    $('#list').querySelectorAll('[data-e]').forEach(a => a.onclick = e => { e.preventDefault(); evDetail(a.dataset.e, load); });
    pager($('#pg'), st, r.total, load);
  });
  $('#q').onchange = $('#fc').onchange = () => { st.page = 1; load(); };
  $('#exp').onclick = guard(() => download('/evidence/export?' + qs({ case_id: $('#fc').value }), 'evidence_inventory.csv'));
  if ($('#up')) $('#up').onclick = () => modal('Register evidence', field('Case', 'case_id', { type: 'select', req: 1, opts: cs.filter(c => !['closed', 'archived'].includes(c.status)).map(c => [c.id, c.ref + ' - ' + c.title]) }) + field('Evidence type', 'evidence_type', { type: 'select', opts: ['document', 'image', 'archive', 'system_log', 'text', 'other'] }) + field('File', 'file', { type: 'file', req: 1 }) + field('Source', 'source', { req: 1 }) + field('Acquisition method', 'acquisition_method', { req: 1 }) + field('Acquisition date/time (ISO, e.g. 2026-10-19T10:00:00Z)', 'acquisition_date') + field('Submitted by', 'submitted_by', { req: 1 }) + field('Received by', 'received_by', { req: 1 }) + field('Description', 'description', { type: 'textarea' }) + '<p class="muted">The original is stored as a read-only reference copy and hashed with SHA-256 during ingestion.</p><button class="btn primary">Upload</button>', async (f, fd) => { await api('/evidence', { method: 'POST', form: fd }); toast('Evidence registered and hashed'); load(); });
  load();
};
const imgPrev = (id, mime, cls = 'evimg') => (mime || '').startsWith('image/') ? `<img class="${cls}" data-prev="${id}" alt="Evidence image preview">` : '';
// load previews as authenticated blobs (an <img src> request cannot send the JWT)
async function loadPreviews(root = document) {
  for (const img of root.querySelectorAll('img[data-prev]')) {
    try {
      const r = await api(`/evidence/${img.dataset.prev}/preview`, { raw: true });
      const url = URL.createObjectURL(await r.blob());
      img.src = url; img.onload = () => URL.revokeObjectURL(url);
    } catch { img.style.display = 'none'; }
  }
}

async function evDetail(id, after) {
  const e = await api('/evidence/' + id), ic = await api('/integrity/' + id);
  const m = modal(e.ref + ' - ' + e.original_filename, `${imgPrev(id, e.mime)}${kv({ Case: e.case_ref, Type: e.evidence_type, Detected_MIME: e.mime, Size: e.size + ' bytes', 'SHA-256 (reference)': e.sha256, 'Hash calculated': fmt(e.hashed_at), Source: e.source, 'Acquisition method': e.acquisition_method, 'Acquisition time': e.acquisition_date, 'Submitted by': e.submitted_by, 'Received by': e.received_by, Custodian: e.custodian, Status: e.status, Description: e.description })}
  <div class="row"><button type="button" class="btn primary" id="vf">Verify integrity</button><button type="button" class="btn" id="dl">Download original</button></div><div id="vr"></div><h3>Integrity history</h3><div id="ih">${ihtml(ic)}</div>`, null, true);
  m.bg.querySelector('#vf').onclick = guard(async () => { const r = await api(`/integrity/${id}/verify`, { method: 'POST' }); m.bg.querySelector('#vr').innerHTML = `<div class="note">${badge(r.result)} ${esc(r.message)}</div>`; m.bg.querySelector('#ih').innerHTML = ihtml(await api('/integrity/' + id)); });
  m.bg.querySelector('#dl').onclick = guard(() => download(`/evidence/${id}/download`, e.original_filename));
  loadPreviews(m.bg);
}
const ihtml = ic => table([['Time', r => fmt(r.at)], ['Result', r => badge(r.result)], ['By', r => esc(r.by_user)], ['Calculated', r => `<code>${esc(r.calculated || '-')}</code>`]], ic, 'Not verified yet.');

pages.analysis = async v => {
  const items = await evOptions();
  v.innerHTML = `<h1>File Analysis</h1><div class="note">Runs on a separate working copy. Files are never executed. Observations are facts; interpretations are tentative.</div><div class="row">${evSel(items)}${can('analysis:run') ? '<button class="btn primary" id="run">Run analysis</button>' : ''}</div><div id="out"></div>`;
  const show = guard(async () => { const id = $('#ev').value; if (!id) return $('#out').innerHTML = '<div class="empty">Register evidence first.</div>'; const h = await api('/file-analysis/' + id); $('#out').innerHTML = h.length ? h.map(j => `<div class="card"><h2>${fmt(j.created_at)} ${badge(j.status)}</h2>${j.error ? `<p class="error">${esc(j.error)}</p>` : ''}${j.result ? `<h3>Observations</h3>${kv(j.result.observations)}<h3>Interpretations (tentative)</h3>${j.result.interpretations.map(i => `<div class="alert">${esc(i)}</div>`).join('') || '<span class="muted">None</span>'}<h3>Warnings</h3>${j.result.warnings.map(i => `<div class="alert">${esc(i)}</div>`).join('') || '<span class="muted">None</span>'}<h3>Tools</h3>${kv(j.result.tools)}` : ''}</div>`).join('') : '<div class="empty">No analysis yet.</div>'; });
  $('#ev').onchange = show; if ($('#run')) $('#run').onclick = guard(async () => { await api('/file-analysis/' + $('#ev').value, { method: 'POST' }); toast('Analysis finished'); show(); });
  show();
};

pages.logs = async v => {
  const items = await evOptions(), st = { page: 1, size: 25 };
  v.innerHTML = `<h1>Log Analysis</h1><div class="note">Supports JSON Lines and timestamped text logs. Alerts are indicators requiring review, not proof of wrongdoing.</div><div class="row">${evSel(items)}${can('analysis:run') ? '<button class="btn primary" id="run">Parse &amp; analyze</button>' : ''}<button class="btn" id="ex">Export normalized CSV</button></div><div id="sum"></div><div class="card"><div class="row"><select id="et" aria-label="Event type"><option value="">All types</option>${['auth_failure', 'auth_success', 'privilege', 'general'].map(x => `<option>${x}</option>`).join('')}</select><input id="src" placeholder="Source"><input id="kw" placeholder="Keyword"><input id="t1" placeholder="From (ISO)"><input id="t2" placeholder="To (ISO)"></div><div id="list"></div><div class="pager" id="pg"></div></div>`;
  const sum = guard(async () => { const id = $('#ev').value; if (!id) return; const s = (await api(`/log-analysis/${id}/summary`))[0]; $('#sum').innerHTML = !s ? '' : s.status === 'failed' ? `<div class="card error">${esc(s.error)}</div>` : `<div class="card"><h2>Latest analysis ${fmt(s.created_at)}</h2>${kv(s.result.stats)}<h3>Indicators requiring review (${s.result.alerts.length})</h3>${s.result.alerts.map(a => `<div class="alert"><b>${esc(a.rule)}</b>: ${esc(a.text)}<br><small class="muted">${esc(a.disclaimer)}</small></div>`).join('') || '<span class="muted">None triggered</span>'}<h3>Event groups</h3>${table([['Type', g => esc(g.event_type)], ['Source', g => esc(g.source)], ['Count', g => g.count]], s.result.groups)}<h3>Malformed / unsupported lines</h3>${s.result.errors.map(e => `<div>line ${e.line}: ${esc(e.error)}</div>`).join('') || '<span class="muted">None</span>'}</div>`; });
  const flt = () => qs({ event_type: $('#et').value, source: $('#src').value, q: $('#kw').value, start: $('#t1').value, end: $('#t2').value });
  const load = guard(async () => { const id = $('#ev').value; if (!id) return; const r = await api(`/log-analysis/${id}/events?` + flt() + `&page=${st.page}&size=${st.size}`); $('#list').innerHTML = table([['Line', e => e.line_no], ['UTC time', e => `${fmt(e.ts_utc)}<br><small class="muted" title="${esc(e.ts_note)}">${esc(e.ts_original || '')}</small>`], ['Type', e => badge(e.event_type)], ['Source', e => esc(e.source || '-')], ['User', e => esc(e.username || '-')], ['Message', e => esc(e.message)]], r.items, 'No parsed events. Run the analysis first.'); pager($('#pg'), st, r.total, load); });
  ['ev', 'et', 'src', 'kw', 't1', 't2'].forEach(i => $('#' + i).onchange = () => { st.page = 1; if (i === 'ev') sum(); load(); });
  $('#ex').onclick = guard(() => download(`/log-analysis/${$('#ev').value}/export?` + flt(), 'normalized_log.csv'));
  if ($('#run')) $('#run').onclick = guard(async () => { const j = await api('/log-analysis/' + $('#ev').value, { method: 'POST' }); toast(j.status === 'completed' ? 'Log analysis finished' : (j.error || 'Failed'), j.status !== 'completed'); sum(); load(); });
  sum(); load();
};

pages.timeline = async v => {
  const cs = (await api('/cases?size=100')).items;
  v.innerHTML = `<h1>Timeline Analysis</h1><div class="note">All times normalized to UTC. Original values and assumptions are shown. Missing times are never invented.</div><div class="row"><select id="tc" aria-label="Case">${cs.map(c => `<option value="${c.id}">${esc(c.ref)} - ${esc(c.title)}</option>`).join('') || '<option value="">(no cases)</option>'}</select><select id="cat" aria-label="Category"><option value="">All categories</option>${['analyst', 'metadata', 'log', 'custody', 'acquisition'].map(x => `<option>${x}</option>`).join('')}</select><select id="ord"><option value="asc">Oldest first</option><option value="desc">Newest first</option></select><input id="t1" placeholder="From (ISO)"><input id="t2" placeholder="To (ISO)">${can('timeline:write') ? '<button class="btn primary" id="add">Add analyst event</button>' : ''}</div><div class="card"><div id="out"></div></div>`;
  const load = guard(async () => {
    if (!$('#tc').value) return $('#out').innerHTML = '<div class="empty">No cases available.</div>';
    const r = await api('/timeline?' + qs({ case_id: $('#tc').value, category: $('#cat').value, order: $('#ord').value, start: $('#t1').value, end: $('#t2').value }));
    const it = i => `<div class="it ${esc(i.category)}"><b>${esc(i.title)}</b> ${badge(i.category)} ${i.evidence_ref ? `<span class="badge">${esc(i.evidence_ref)}</span>` : ''}<br><span class="mono">${fmt(i.utc)}</span> <small class="muted">(original: ${esc(i.original || 'n/a')}; ${esc(i.note || '')})</small><div>${esc(i.details)}</div></div>`;
    $('#out').innerHTML = (r.items.length ? `<div class="tl">${r.items.map(it).join('')}</div>` : '<div class="empty">No dated events.</div>') + (r.truncated ? '<p class="muted">Result truncated - narrow the filters.</p>' : '') + (r.undated.length ? `<h3>Missing / invalid timestamps (${r.undated.length})</h3><div class="tl">${r.undated.map(it).join('')}</div>` : '');
  });
  ['tc', 'cat', 'ord', 't1', 't2'].forEach(i => $('#' + i).onchange = load);
  if ($('#add')) $('#add').onclick = () => modal('Add analyst event', field('Title', 'title', { req: 1 }) + field('Details', 'details', { type: 'textarea' }) + field('Event time (ISO-8601, include timezone if known)', 'original_ts', { req: 1 }) + field('If the time has no timezone: offset from UTC in minutes (e.g. 120 for UTC+2)', 'tz_offset_minutes', { type: 'number', value: '0' }) + '<button class="btn primary">Add</button>', async (f, fd) => { const o = Object.fromEntries(fd); o.case_id = $('#tc').value; o.tz_offset_minutes = +o.tz_offset_minutes || 0; await api('/timeline', { method: 'POST', body: o }); toast('Event added'); load(); });
  load();
};

pages.custody = async v => {
  const items = await evOptions();
  v.innerHTML = `<h1>Chain of Custody</h1><div class="note">Append-only history. Entries cannot be edited or deleted; corrections are recorded as new notes.</div><div class="row">${evSel(items)}<button class="btn" id="pr">Print record</button></div><div id="out"></div>`;
  const load = guard(async () => {
    const id = $('#ev').value; if (!id) return $('#out').innerHTML = '<div class="empty">No evidence.</div>';
    const r = await api('/chain-of-custody/' + id), dir = can('custody:transfer') ? await api('/users/directory') : [];
    $('#out').innerHTML = `<div class="card"><h2>${esc(r.evidence.ref)} - ${esc(r.evidence.original_filename)}</h2>${imgPrev(id, r.evidence.mime, 'evimg custody-img')}${kv({ Case: r.evidence.case_ref, 'Current custodian': r.evidence.custodian, Status: r.evidence.status, 'SHA-256': r.evidence.sha256 })}</div>
    <div class="card">${table([['Time (UTC)', e => fmt(e.created_at)], ['Action', e => badge(e.action)], ['From', e => esc(e.from_user || '-')], ['To', e => esc(e.to_user || '-')], ['By', e => esc(e.by_user)], ['Reason / notes', e => esc(e.reason + (e.notes ? ' | ' + e.notes : ''))], ['Receipt', e => e.ack_status ? (e.ack_status === 'pending' && e.to_user_id === ME.id ? `<button class="btn sm primary" data-a="${e.id}">Acknowledge</button>` : badge(e.ack_status)) : '-']], r.events)}</div>
    ${can('custody:transfer') ? `<div class="card no-print"><h2>Transfer custody</h2><form id="tf"><div class="row"><select name="to_user_id">${dir.filter(u => u.id !== ME.id).map(u => `<option value="${u.id}">${esc(u.full_name)}</option>`).join('')}</select><input name="reason" placeholder="Reason" required><input name="notes" placeholder="Notes"><button class="btn primary">Transfer</button></div></form></div>` : ''}`;
    $('#out').querySelectorAll('[data-a]').forEach(b => b.onclick = guard(async () => { await api(`/chain-of-custody/${id}/acknowledge/${b.dataset.a}`, { method: 'POST' }); toast('Receipt acknowledged'); load(); }));
    loadPreviews($('#out'));
    if ($('#tf')) $('#tf').onsubmit = guard(async e => { e.preventDefault(); await api(`/chain-of-custody/${id}/transfer`, { method: 'POST', body: Object.fromEntries(new FormData(e.target)) }); toast('Transfer recorded - awaiting acknowledgment'); load(); });
  });
  $('#ev').onchange = load; $('#pr').onclick = () => window.print(); load();
};

pages.reports = async v => {
  const cs = (await api('/cases?size=100')).items;
  v.innerHTML = `<h1>Forensic Reports</h1><div class="row"><select id="rc" aria-label="Case">${cs.map(c => `<option value="${c.id}">${esc(c.ref)} - ${esc(c.title)}</option>`).join('') || '<option value="">(no cases)</option>'}</select></div>${can('report:create') ? `<div class="card"><h2>New report</h2><form id="rf">${field('Limitations and unresolved questions', 'limitations', { type: 'textarea' })}${field('Investigator notes', 'notes', { type: 'textarea' })}${field('Conclusions (your interpretation)', 'conclusions', { type: 'textarea' })}<div id="pv"></div><div class="row"><button type="button" class="btn" id="prev">Preview</button><button class="btn primary">Generate PDF</button></div></form></div>` : ''}<div class="card"><h2>Generated reports</h2><div id="list"></div></div>`;
  const load = guard(async () => { $('#list').innerHTML = table([['Report', r => esc(r.ref)], ['Case', r => esc(r.case_ref)], ['Version', r => 'v' + r.version], ['Author', r => esc(r.by_user)], ['Created', r => fmt(r.created_at)], ['', r => `<button class="btn sm" data-d="${r.id}" data-n="${esc(r.ref)}">Download</button>`]], await api('/reports?' + qs({ case_id: $('#rc').value })), 'No reports yet.'); $('#list').querySelectorAll('[data-d]').forEach(b => b.onclick = guard(() => download(`/reports/${b.dataset.d}/download`, b.dataset.n + '.pdf'))); });
  const body = () => ({ case_id: $('#rc').value, ...Object.fromEntries(new FormData($('#rf'))) });
  if ($('#rf')) { $('#prev').onclick = guard(async () => { const p = await api('/reports/preview', { method: 'POST', body: body() }); $('#pv').innerHTML = `<div class="note"><b>${esc(p.case.ref)}</b> - ${esc(p.case.title)} (v${p.next_version})<br>Investigators: ${esc(p.investigators.join(', '))}<br>Timeline events: ${p.timeline_events}</div>${table([['Evidence', e => esc(e.ref)], ['File', e => esc(e.file)], ['Integrity', e => badge(e.last_integrity)], ['File analysis', e => e.file_analysis], ['Log analysis', e => e.log_analysis], ['Custody events', e => e.custody_events]], p.evidence, 'No evidence in this case.')}`; });
    $('#rf').onsubmit = guard(async e => { e.preventDefault(); const r = await api('/reports', { method: 'POST', body: body() }); toast('Report ' + r.ref + ' generated'); load(); }); }
  $('#rc').onchange = load; load();
};

pages.audit = async v => {
  const st = { page: 1, size: 20 };
  v.innerHTML = `<h1>Audit Trail</h1><div class="note">Append-only, hash-chained log. Limitation: an administrator with database access could still tamper with the chain; production use needs external write-once storage.</div><div class="row"><input id="q" placeholder="Search actor or action" aria-label="Search">${can('users:manage') ? '<button class="btn" id="ver">Verify chain integrity</button>' : ''}</div><div id="vr"></div><div class="card"><div id="list"></div><div class="pager" id="pg"></div></div>`;
  const load = guard(async () => { const r = await api('/audit?' + qs({ q: $('#q').value, page: st.page, size: st.size })); $('#list').innerHTML = table([['#', e => e.seq], ['Time', e => fmt(e.ts)], ['Actor', e => esc(e.actor || '-')], ['Action', e => esc(e.action)], ['Object', e => esc((e.object_type || '') + ' ' + (e.object_id || '').slice(0, 8))], ['Outcome', e => badge(e.outcome)], ['Details', e => `<code>${esc(JSON.stringify(e.meta))}</code>`]], r.items, 'No audit events.'); pager($('#pg'), st, r.total, load); });
  $('#q').onchange = () => { st.page = 1; load(); };
  if ($('#ver')) $('#ver').onclick = guard(async () => { const r = await api('/audit/verify'); $('#vr').innerHTML = `<div class="note">${r.valid ? 'Chain valid - ' + r.checked + ' events verified.' : 'CHAIN BROKEN at event #' + r.broken_at_seq}</div>`; });
  load();
};

pages.users = async v => {
  const load = guard(async () => {
    const us = await api('/users');
    v.innerHTML = `<h1>User Management</h1><div class="row"><span class="spacer"></span><button class="btn primary" id="new">New user</button></div><div class="card">${table([['User', u => `${esc(u.full_name)}<br><small class="muted">${esc(u.username)}</small>`], ['Role', u => `<select data-r="${u.id}">${['admin', 'lead', 'analyst', 'custodian', 'reviewer'].map(r => `<option ${r === u.role ? 'selected' : ''}>${r}</option>`).join('')}</select>`], ['Active', u => badge(u.is_active ? 'active' : 'inactive')], ['', u => `<button class="btn sm" data-t="${u.id}" data-a="${u.is_active}">${u.is_active ? 'Deactivate' : 'Activate'}</button> <button class="btn sm" data-p="${u.id}">Reset password</button>`]], us)}</div>`;
    v.querySelectorAll('[data-r]').forEach(s => s.onchange = guard(async () => { await api('/users/' + s.dataset.r, { method: 'PATCH', body: { role: s.value } }); toast('Role updated'); }));
    v.querySelectorAll('[data-t]').forEach(b => b.onclick = guard(async () => { if (!confirm('Change account status?')) return; await api('/users/' + b.dataset.t, { method: 'PATCH', body: { is_active: b.dataset.a !== 'true' } }); load(); }));
    v.querySelectorAll('[data-p]').forEach(b => b.onclick = guard(async () => { if (!confirm('Reset this password?')) return; const r = await api(`/users/${b.dataset.p}/reset-password`, { method: 'POST' }); modal('Temporary password', `<p>Shown once. Give it to the user securely:</p><pre>${esc(r.temporary_password)}</pre>`); }));
    $('#new').onclick = () => modal('New user', field('Username', 'username', { req: 1 }) + field('Full name', 'full_name', { req: 1 }) + field('Email', 'email') + field('Role', 'role', { type: 'select', opts: ['lead', 'analyst', 'custodian', 'reviewer', 'admin'] }) + field('Initial password (min 10, letters+digits)', 'password', { type: 'password', req: 1 }) + '<button class="btn primary">Create</button>', async (f, fd) => { await api('/users', { method: 'POST', body: Object.fromEntries(fd) }); toast('User created'); load(); });
  }); load();
};

pages.settings = async v => {
  const s = await api('/settings'), r = s.log_rules;
  v.innerHTML = `<h1>System Settings</h1><div class="note">${esc(s.notice)}</div><div class="card"><h2>Configuration (read-only, set via environment)</h2>${kv({ 'Max upload (MB)': s.max_upload_mb, 'Allowed extensions': s.allowed_extensions.join(', '), 'Retention (days)': s.retention_days, 'Token lifetime (min)': s.access_token_minutes, Database: s.database })}</div>
  <div class="card"><h2>Log-analysis rules</h2><form id="rf">${field('Auth-failure threshold', 'auth_failure_threshold', { type: 'number', value: r.auth_failure_threshold })}${field('Window (minutes)', 'window_minutes', { type: 'number', value: r.window_minutes })}${field('Privilege keywords (comma separated)', 'privilege_keywords', { value: r.privilege_keywords.join(', ') })}${field('Custom keywords (comma separated)', 'custom_keywords', { value: r.custom_keywords.join(', ') })}<button class="btn primary">Save rules</button></form></div>`;
  const list = x => x.split(',').map(s => s.trim()).filter(Boolean);
  $('#rf').onsubmit = guard(async e => { e.preventDefault(); const o = Object.fromEntries(new FormData(e.target)); await api('/settings/log_rules', { method: 'PUT', body: { auth_failure_threshold: +o.auth_failure_threshold, window_minutes: +o.window_minutes, privilege_keywords: list(o.privilege_keywords), custom_keywords: list(o.custom_keywords) } }); toast('Rules saved'); });
};

// ---------------- shell ----------------
const NAV = [['dashboard', 'Dashboard', '\u25A3'], ['cases', 'Investigation Cases', '\u25A4'], ['evidence', 'Digital Evidence', '\u25C9'], ['analysis', 'File Analysis', '\u2315'], ['logs', 'Log Analysis', '\u2261'], ['timeline', 'Timeline Analysis', '\u231A'], ['custody', 'Chain of Custody', '\u26D3'], ['reports', 'Forensic Reports', '\u2637'], ['audit', 'Audit Trail', '\u2691'], ['users', 'User Management', '\u263A', 'users:manage'], ['settings', 'System Settings', '\u2699', 'settings:manage']];
async function route() {
  if (!ME) return;
  const name = (location.hash.slice(1) || 'dashboard'), item = NAV.find(n => n[0] === name) || NAV[0];
  $('#nav').innerHTML = NAV.filter(n => !n[3] || can(n[3])).map(n => `<a href="#${n[0]}" class="${n[0] === item[0] ? 'active' : ''}"><span class="ic" aria-hidden="true">${n[2]}</span><span class="label">${n[1]}</span></a>`).join('');
  const v = $('#view'); v.innerHTML = '<div class="empty">Loading&hellip;</div>';
  $('#sidebar').classList.remove('open');
  try { if (item[3] && !can(item[3])) throw new Error('Not permitted'); await pages[item[0]](v); } catch (e) { v.innerHTML = `<div class="card"><h2>Something went wrong</h2><p class="error">${esc(e.message)}</p></div>`; }
}
function pwModal(force) { modal('Change password', (force ? '<p class="error">You must change your temporary password.</p>' : '') + field('Current password', 'current_password', { type: 'password', req: 1 }) + field('New password (min 10, letters+digits)', 'new_password', { type: 'password', req: 1 }) + '<button class="btn primary">Change</button>', async (f, fd) => { await api('/auth/change-password', { method: 'POST', body: Object.fromEntries(fd) }); toast('Password changed'); ME.must_change_password = false; }); }
let MFA_TOKEN = null, MFA_RECOVERY = false;
function showMFA(err) {
  $('#login').classList.add('hidden'); $('#mfaForm').classList.remove('hidden');
  $('#mfaRecovery').textContent = MFA_RECOVERY ? 'Use an authenticator code' : 'Use a recovery code';
  $('#mfaForm').querySelector('label').firstChild.textContent = MFA_RECOVERY ? 'Recovery code' : 'Authenticator code';
  $('#mfaForm input[name=code]').value = ''; $('#mfaErr').textContent = err || '';
  $('#mfaForm input[name=code]').focus();
}
async function finishMFA(path) {
  try {
    const r = await api('/auth/mfa/' + path, { method: 'POST', body: { mfa_token: MFA_TOKEN, code: $('#mfaForm input[name=code]').value } });
    TOKEN = r.access_token; sessionStorage.setItem('dfis_t', TOKEN);
    $('#mfaForm').reset(); $('#mfaForm').classList.add('hidden'); MFA_TOKEN = null; enter(r.me);
  } catch (x) { showMFA(x.message); }
}
$('#mfaForm').onsubmit = e => { e.preventDefault(); finishMFA(MFA_RECOVERY ? 'verify-recovery' : 'verify'); };
$('#mfaRecovery').onclick = () => { MFA_RECOVERY = !MFA_RECOVERY; showMFA(); };
function mfaModal() {
  modal('Two-factor authentication', '<div id="mfaStep1">' + field('Authenticator code (from your app)', 'code', { req: 1 }) + '<p class="muted">Enabling TOTP requires a valid code. Disable requires a code too.</p><button type="button" class="btn primary" id="mfaGo">Continue</button></div><div id="mfaStep2" class="hidden"></div>', null, true);
}
async function twoFactorManager() {
  const st = await api('/auth/mfa/status');
  if (!st.mfa_enabled) {
    modal('Enable two-factor authentication', '<div class="note">1. Scan the QR code with an authenticator app (Google/Microsoft Authenticator, Authy).<br>2. Enter the 6-digit code it shows to activate 2FA.</div><div id="qrbox" class="note">Generating&hellip;</div>' + field('6-digit code', 'code', { req: 1 }) + '<button class="btn primary">Enable</button>', async (f, fd) => {
      const r = await api('/auth/mfa/enable', { method: 'POST', body: Object.fromEntries(fd) });
      toast('Two-factor authentication enabled');
      modal('Save your recovery codes', '<p class="error">Shown once. Each works one time to sign in if you lose your authenticator.</p><pre>' + r.recovery_codes.join('\n') + '</pre>');
      ME.mfa_enabled = true; $('#mfaBtn').textContent = '2FA: on';
    });
    const setup = await api('/auth/mfa/setup', { method: 'POST' });
    $('#qrbox').innerHTML = `<img alt="QR code" src="data:image/png;base64,${setup.qr_png_base64}"><p class="mono">${esc(setup.secret)}</p>`;
  } else {
    modal('Disable two-factor authentication', '<p class="error">This removes the second factor from your account.</p>' + field('6-digit code to confirm', 'code', { req: 1 }) + '<button class="btn primary">Disable</button>', async (f, fd) => { await api('/auth/mfa/disable', { method: 'POST', body: Object.fromEntries(fd) }); ME.mfa_enabled = false; $('#mfaBtn').textContent = '2FA: off'; toast('Two-factor authentication disabled'); });
  }
}
function enter(me) { ME = me; $('#login').classList.add('hidden'); $('#mfaForm').classList.add('hidden'); $('#app').classList.remove('hidden'); $('#whoami').textContent = `${me.full_name} (${me.role})`; $('#mfaBtn').classList.remove('hidden'); $('#mfaBtn').textContent = me.mfa_enabled ? '2FA: on' : '2FA: off'; route(); if (me.must_change_password) pwModal(true); }
async function logout(silent) { try { if (TOKEN && !silent) await api('/auth/logout', { method: 'POST' }); } catch { } TOKEN = null; ME = null; sessionStorage.removeItem('dfis_t'); $('#app').classList.add('hidden'); $('#login').classList.add('hidden'); $('#mfaForm').classList.add('hidden'); MFA_TOKEN = null; MFA_RECOVERY = false; $('#login').classList.remove('hidden'); }
$('#loginForm').onsubmit = async e => { e.preventDefault(); $('#loginErr').textContent = ''; try { const r = await api('/auth/login', { method: 'POST', body: Object.fromEntries(new FormData(e.target)) }); if (r.mfa_required) { MFA_TOKEN = r.mfa_token; MFA_RECOVERY = false; e.target.reset(); showMFA(); return; } TOKEN = r.access_token; sessionStorage.setItem('dfis_t', TOKEN); e.target.reset(); enter(r.me); } catch (x) { $('#loginErr').textContent = x.message; } };
$('#logout').onclick = () => logout(); $('#pwBtn').onclick = () => pwModal(false); $('#mfaBtn').onclick = guard(twoFactorManager);
$('#toggle').onclick = () => { const s = $('#sidebar'); innerWidth < 800 ? s.classList.toggle('open') : s.classList.toggle('collapsed'); };
addEventListener('hashchange', route);
(async () => { if (TOKEN) { try { enter(await api('/auth/me')); return; } catch { } } $('#login').classList.remove('hidden'); })();
