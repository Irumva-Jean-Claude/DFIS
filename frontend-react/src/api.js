let _token = sessionStorage.getItem('dfis_t')

export const getToken = () => _token
export const setToken = t => {
  _token = t
  if (t) sessionStorage.setItem('dfis_t', t)
  else sessionStorage.removeItem('dfis_t')
}

export const fmt = d => d ? String(d).replace('T', ' ').replace('Z', ' UTC') : '-'
export const qs = o => Object.entries(o).filter(([, v]) => v !== '' && v != null).map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&')

export async function api(path, { method = 'GET', body, form, raw } = {}) {
  const h = {}
  if (_token) h.Authorization = 'Bearer ' + _token
  let b
  if (form) b = form
  else if (body !== undefined) { h['Content-Type'] = 'application/json'; b = JSON.stringify(body) }
  const r = await fetch('/api/v1' + path, { method, headers: h, body: b })
  if (r.status === 401 && !path.startsWith('/auth/login')) {
    setToken(null)
    throw new Error('Session expired - please sign in again')
  }
  if (!r.ok) {
    let m = r.statusText
    try {
      const j = await r.json()
      m = typeof j.detail === 'string' ? j.detail : j.detail.map(x => (x.loc || []).slice(-1) + ': ' + x.msg).join('; ')
    } catch {}
    throw new Error(m)
  }
  return raw ? r : r.json()
}

export async function download(path, name) {
  const r = await api(path, { raw: true })
  const a = document.createElement('a')
  a.href = URL.createObjectURL(await r.blob())
  a.download = name
  a.click()
  setTimeout(() => URL.revokeObjectURL(a.href), 2000)
}

export async function evOptions(caseId) {
  const r = await api('/evidence?' + qs({ size: 200, case_id: caseId || '' }))
  return r.items
}
