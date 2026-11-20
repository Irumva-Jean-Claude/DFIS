export default function Bars({ data, empty = 'No data yet' }) {
  if (!data?.length) return <div className="empty">{empty}</div>
  const max = Math.max(1, ...data.map(d => d.value))
  return (
    <div className="bars">
      {data.map((d, i) => (
        <div key={i} className="r">
          <span>{d.label}</span>
          <div className="bar"><i style={{ width: `${d.value / max * 100}%` }} /></div>
          <b>{d.value}</b>
        </div>
      ))}
    </div>
  )
}
