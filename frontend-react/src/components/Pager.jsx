export default function Pager({ page, size, total, onChange }) {
  const pages = Math.max(1, Math.ceil(total / size))
  return (
    <div className="pager">
      <span className="muted">{total} record(s) — page {page}/{pages}</span>
      <button className="btn sm" disabled={page <= 1} onClick={() => onChange(page - 1)}>Prev</button>
      <button className="btn sm" disabled={page >= pages} onClick={() => onChange(page + 1)}>Next</button>
    </div>
  )
}
