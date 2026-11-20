import { fmt } from '../api'

export default function KeyValue({ data }) {
  const entries = Object.entries(data).filter(([, v]) => v != null && v !== '')
  if (!entries.length) return null
  return (
    <dl className="kv">
      {entries.map(([k, v]) => (
        <div key={k} style={{ display: 'contents' }}>
          <dt>{k}</dt>
          <dd>
            {typeof v === 'object'
              ? <pre>{JSON.stringify(v, null, 2)}</pre>
              : String(v)}
          </dd>
        </div>
      ))}
    </dl>
  )
}
