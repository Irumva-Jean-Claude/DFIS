import { createContext, useContext, useState, useEffect } from 'react'
import { api, setToken, getToken } from '../api'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [me, setMe] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (getToken()) {
      api('/auth/me')
        .then(u => { setMe(u); setLoading(false) })
        .catch(() => { setToken(null); setLoading(false) })
    } else {
      setLoading(false)
    }
  }, [])

  const login = user => { setMe(user) }

  const logout = async (silent = false) => {
    try { if (!silent) await api('/auth/logout', { method: 'POST' }) } catch {}
    setToken(null)
    setMe(null)
  }

  const can = p => me?.permissions?.includes(p) ?? false

  if (loading) return null

  return (
    <AuthContext.Provider value={{ me, login, logout, can }}>
      {children}
    </AuthContext.Provider>
  )
}

export const useAuth = () => useContext(AuthContext)
