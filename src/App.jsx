import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { InvestigationProvider } from './context/InvestigationContext'
import Layout from './components/layout/Layout'
import Dashboard from './pages/Dashboard'
import Investigate from './pages/Investigate'
import Reports from './pages/Reports'

export default function App() {
  return (
    <InvestigationProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<Navigate to="/dashboard" replace />} />
            <Route path="dashboard" element={<Dashboard />} />
            <Route path="investigate" element={<Investigate />} />
            <Route path="investigate/:id" element={<Investigate />} />
            <Route path="reports" element={<Reports />} />
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </InvestigationProvider>
  )
}
