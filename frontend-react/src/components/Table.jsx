export default function Table({ cols, rows, empty = 'No records yet.' }) {
  if (!rows.length) return <div className="empty">{empty}</div>
  return (
    <div className="tablewrap">
      <table>
        <thead>
          <tr>{cols.map(c => <th key={c.key ?? c.label}>{c.label}</th>)}</tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i}>
              {cols.map(c => <td key={c.key ?? c.label}>{c.render(row)}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
