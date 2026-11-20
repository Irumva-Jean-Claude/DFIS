import { createContext, useContext, useState, useCallback } from 'react'

const ToastContext = createContext(null)

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([])

  const toast = useCallback((msg, err = false) => {
    const id = Date.now() + Math.random()
    setToasts(t => [...t, { id, msg, err }])
    setTimeout(() => setToasts(t => t.filter(x => x.id !== id)), 4500)
  }, [])

  return (
    <ToastContext.Provider value={toast}>
      {children}
      <div id="toasts" aria-live="polite">
        {toasts.map(t => (
          <div key={t.id} className={'toast' + (t.err ? ' err' : '')}>{t.msg}</div>
        ))}
      </div>
    </ToastContext.Provider>
  )
}

export const useToast = () => useContext(ToastContext)
