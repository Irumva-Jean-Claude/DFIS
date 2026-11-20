export default function Help() {
  const sections = [
    {
      title: 'Getting started',
      color: 'var(--blue)',
      items: [
        ['Logging in', 'Enter your username and password. If two-factor authentication (2FA) is enabled, you will be prompted for a 6-digit code from your authenticator app.'],
        ['Changing your password', 'Click the "Password" button in the top bar. You must change a temporary password on first login.'],
        ['Two-factor authentication', 'Click "2FA" in the top bar to enable or disable TOTP-based authentication. Store recovery codes securely — they are shown only once.'],
        ['Session timeout', 'Sessions automatically expire after 30 minutes of inactivity. You will receive a warning 1 minute before expiry.'],
      ]
    },
    {
      title: 'Case management',
      color: 'var(--green)',
      items: [
        ['Creating a case', 'Go to Investigation Cases → New case. Fill in the title, description, category, and priority.'],
        ['Case statuses', 'open → active → closed → archived. Transitions are one-way (except closed ↔ active). Archived cases have a retention period set automatically.'],
        ['Assigning investigators', 'Open a case and use the Assign investigator panel. The investigator will receive an email notification.'],
        ['Case history', 'Every status change, assignment, and update is recorded in the case history panel.'],
      ]
    },
    {
      title: 'Digital evidence',
      color: 'var(--cyan)',
      items: [
        ['Registering evidence', 'Go to Digital Evidence → Register evidence. Upload the file and fill in acquisition details. The system calculates and stores the SHA-256 hash immediately.'],
        ['Integrity verification', 'Open an evidence item and click Verify integrity. The system recalculates the hash and compares it to the stored reference. A MATCH confirms the file has not changed.'],
        ['Downloading evidence', 'Open an evidence item and click Download original. All downloads are logged in the audit trail.'],
        ['Evidence export', 'Use the Export CSV button to download a full inventory for a case.'],
      ]
    },
    {
      title: 'Chain of custody',
      color: 'var(--amber)',
      items: [
        ['Viewing custody history', 'Go to Chain of Custody, select a case and evidence item. The full custody chain is shown chronologically.'],
        ['Transferring custody', 'Only the current custodian (or admin/lead) can transfer evidence. The recipient must acknowledge receipt.'],
        ['Acknowledging a transfer', 'If evidence has been transferred to you, go to Chain of Custody and click Acknowledge next to the pending transfer.'],
        ['Correction notes', 'Admins can append correction notes to the custody chain. No entry can be edited or deleted.'],
      ]
    },
    {
      title: 'File & log analysis',
      color: 'var(--violet)',
      items: [
        ['File analysis', 'Go to File Analysis, select a case and evidence item, then click Run file analysis. Results include file type, MIME, metadata timestamps, and interpretations.'],
        ['Keyword search', 'After selecting an evidence item, enter comma-separated keywords in the search box. Supported file types: plain text, PDF, DOCX.'],
        ['Log analysis', 'Select a log file evidence item and click Parse log. The system parses JSON Lines and timestamped text logs, detects authentication failures and privilege-escalation indicators.'],
        ['Log export', 'Normalized log events can be exported as CSV using the Export CSV button.'],
      ]
    },
    {
      title: 'Reports & audit',
      color: 'var(--red)',
      items: [
        ['Generating a report', 'Go to Forensic Reports → New report. Select a case, preview the report contents, fill in conclusions and limitations, then click Generate PDF.'],
        ['What the report contains', 'Case summary, full evidence inventory with SHA-256 hashes, chain of custody, integrity check results, file/log analysis findings, and a UTC-normalized timeline.'],
        ['Audit trail', 'All system actions are recorded in a hash-chained audit log. Use Verify chain to cryptographically verify the log has not been tampered with.'],
        ['Audit export', 'Admins can search and paginate the full audit trail. Contact your administrator to export audit records.'],
      ]
    },
    {
      title: 'User management (admin)',
      color: 'var(--muted2)',
      items: [
        ['Creating users', 'Go to User Management → New user. Assign a role and temporary password. The user must change the password at first login.'],
        ['Roles', 'admin — full access. lead — manage cases and users. analyst — run analysis, read evidence. custodian — handle evidence transfers. reviewer — read-only access.'],
        ['Approving accounts', 'If user approval is required (set in .env), new accounts appear in the Pending approval tab. Click Approve to activate.'],
        ['Deactivating users', 'Click Deactivate on any active account. All their active sessions are immediately revoked.'],
      ]
    },
  ]

  return (
    <>
      <h1>Help & User Guide</h1>
      <p className="muted" style={{ marginBottom: 24 }}>
        Reference guide for all features of the Digital Forensics Investigation System.
      </p>

      {sections.map(s => (
        <div key={s.title} className="card" style={{ borderLeftWidth: 3, borderLeftColor: s.color }}>
          <h2 style={{ color: s.color, textTransform: 'none', fontSize: 15, fontWeight: 700, marginBottom: 16 }}>{s.title}</h2>
          <div style={{ display: 'grid', gap: 12 }}>
            {s.items.map(([title, desc]) => (
              <div key={title} style={{ display: 'grid', gridTemplateColumns: '200px 1fr', gap: '6px 16px', alignItems: 'start' }}>
                <strong style={{ color: 'var(--muted2)', fontSize: 13 }}>{title}</strong>
                <span style={{ color: 'var(--text)', fontSize: 13, lineHeight: 1.6 }}>{desc}</span>
              </div>
            ))}
          </div>
        </div>
      ))}

      <div className="card" style={{ borderLeftWidth: 3, borderLeftColor: 'var(--muted)' }}>
        <h2 style={{ color: 'var(--muted)', textTransform: 'none', fontSize: 15, fontWeight: 700 }}>Legal & compliance notice</h2>
        <p style={{ fontSize: 13, lineHeight: 1.8, color: 'var(--muted2)' }}>
          This system maintains an append-only, hash-chained audit trail for all actions. Evidence files are stored with
          SHA-256 reference hashes and cannot be modified after ingestion. Chain of custody records are immutable.
          All user activity is logged including logins, file downloads, analysis runs, and report generation.
          Access to this system is restricted to authorized personnel only. Unauthorized access or misuse may result
          in disciplinary action and/or legal prosecution.
        </p>
      </div>
    </>
  )
}
