import { useEffect } from 'react'
import { createPortal } from 'react-dom'

export default function Modal({ title, children, onClose, wide }) {
  useEffect(() => {
    const fn = e => { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', fn)
    return () => document.removeEventListener('keydown', fn)
  }, [onClose])

  return createPortal(
    <div className="modal-bg" onClick={e => { if (e.target === e.currentTarget) onClose() }}>
      <div className={'modal' + (wide ? ' wide' : '')} role="dialog" aria-modal="true">
        <h2>
          <span>{title}</span>
          <button type="button" className="btn sm ghost" onClick={onClose} aria-label="Close">&times;</button>
        </h2>
        {children}
      </div>
    </div>,
    document.body
  )
}
