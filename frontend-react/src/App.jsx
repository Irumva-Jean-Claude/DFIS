import { HashRouter, Routes, Route, Navigate } from 'react-router-dom'
import { ToastProvider } from './context/ToastContext'
import { AuthProvider, useAuth } from './context/AuthContext'
import Layout from './components/Layout'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Cases from './pages/Cases'
import Evidence from './pages/Evidence'
import FileAnalysis from './pages/FileAnalysis'
import LogAnalysis from './pages/LogAnalysis'
import Timeline from './pages/Timeline'
import Custody from './pages/Custody'
import Reports from './pages/Reports'
import Audit from './pages/Audit'
import Users from './pages/Users'
import Settings from './pages/Settings'
import Help from './pages/Help'

function AppRoutes() {
  const { me } = useAuth()
  if (!me) return <Login />
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/cases" element={<Cases />} />
        <Route path="/evidence" element={<Evidence />} />
        <Route path="/analysis" element={<FileAnalysis />} />
        <Route path="/logs" element={<LogAnalysis />} />
        <Route path="/timeline" element={<Timeline />} />
        <Route path="/custody" element={<Custody />} />
        <Route path="/reports" element={<Reports />} />
        <Route path="/audit" element={<Audit />} />
        <Route path="/users" element={<Users />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="/help" element={<Help />} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </Layout>
  )
}

export default function App() {
  return (
    <HashRouter>
      <ToastProvider>
        <AuthProvider>
          <AppRoutes />
        </AuthProvider>
      </ToastProvider>
    </HashRouter>
  )
}
