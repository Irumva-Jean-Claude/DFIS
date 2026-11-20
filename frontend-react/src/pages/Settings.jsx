import { useState, useEffect } from 'react'
import { api } from '../api'
import { useToast } from '../context/ToastContext'
import KeyValue from '../components/KeyValue'

export default function Settings() {
  const toast = useToast()
  const [cfg, setCfg] = useState(null)
  const [rules, setRules] = useState(null)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    api('/settings').then(d => { setCfg(d); setRules(d.log_rules ? { ...d.log_rules } : null) })
      .catch(err => toast(err.message, true))
  }, [])

  if (!cfg) return <div className="empty">Loading…</div>

  const saveRules = async e => {
    e.preventDefault(); setSaving(true)
    try { const u = await api('/settings/log_rules', { method: 'PUT', body: rules }); setRules(u); toast('Rules saved') }
    catch (err) { toast(err.message, true) }
    finally { setSaving(false) }
  }

  const setArr = (key, val) => setRules(r => ({ ...r, [key]: val.split('\n').map(s => s.trim()).filter(Boolean) }))

  return (
    <>
      <h1>System Settings</h1>

      <div className="card">
        <h2>System information</h2>
        <KeyValue data={{
          'Organization':       cfg.org_name,
          'Version':            cfg.version,
          'Database engine':    cfg.database,
          'Max upload size':    `${cfg.max_upload_mb} MB`,
          'Allowed extensions': cfg.allowed_extensions?.join(', '),
          'Retention period':   `${cfg.retention_days} days`,
          'Token lifetime':     `${cfg.access_token_minutes} minutes`,
          'Session idle timeout': `${cfg.session_idle_minutes} minutes`,
          'User approval required': cfg.require_user_approval ? 'Yes' : 'No',
        }} />
      </div>

      <div className="card">
        <h2>Email notifications</h2>
        <div className={`note ${cfg.email_configured ? '' : 'warn'}`}
          style={{ borderColor: cfg.email_configured ? 'rgba(16,185,129,.3)' : 'rgba(245,158,11,.3)',
                   background: cfg.email_configured ? 'var(--green-bg)' : 'var(--amber-bg)',
                   color: cfg.email_configured ? 'var(--green)' : 'var(--amber)' }}>
          {cfg.email_configured
            ? `✓ Email configured — notifications will be sent from ${cfg.smtp_from}`
            : '⚠ Email not configured — set DFIS_SMTP_HOST, DFIS_SMTP_USER, DFIS_SMTP_PASS, DFIS_SMTP_FROM in your .env file to enable notifications.'}
        </div>
        {cfg.email_configured && (
          <KeyValue data={{
            'SMTP host': cfg.smtp_host,
            'SMTP port': cfg.smtp_port,
            'From address': cfg.smtp_from,
          }} />
        )}
        <p className="muted" style={{ fontSize: 12 }}>
          Notifications are sent for: custody transfers, case assignments, password resets, account approvals.
        </p>
      </div>

      {rules && (
        <div className="card">
          <h2>Log analysis rules</h2>
          <form onSubmit={saveRules}>
            <label>Authentication failure threshold (number of failures)
              <input type="number" value={rules.auth_failure_threshold ?? 5} min={2} max={1000}
                onChange={e => setRules(r => ({ ...r, auth_failure_threshold: +e.target.value }))} />
            </label>
            <label>Detection window (minutes)
              <input type="number" value={rules.window_minutes ?? 5} min={1} max={1440}
                onChange={e => setRules(r => ({ ...r, window_minutes: +e.target.value }))} />
            </label>
            <label>Privilege-escalation keywords (one per line)
              <textarea rows={5} value={(rules.privilege_keywords || []).join('\n')}
                onChange={e => setArr('privilege_keywords', e.target.value)} />
            </label>
            <label>Custom alert keywords (one per line)
              <textarea rows={5} value={(rules.custom_keywords || []).join('\n')}
                onChange={e => setArr('custom_keywords', e.target.value)} />
            </label>
            <button className="btn primary" disabled={saving}>{saving ? 'Saving…' : 'Save rules'}</button>
          </form>
        </div>
      )}
    </>
  )
}
