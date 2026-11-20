export default function Badge({ value }) {
  if (value == null) return '-'
  const v = String(value)
  return <span className={`badge b-${v.toLowerCase()}`}>{v}</span>
}
