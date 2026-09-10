import { NavLink, useNavigate } from 'react-router-dom'
import { Shield } from 'lucide-react'
import './Navbar.css'

export default function Navbar() {
  const navigate = useNavigate()

  return (
    <nav className="navbar" role="navigation" aria-label="Main navigation">
      {/* Left — Brand */}
      <div
        className="navbar-brand"
        onClick={() => navigate('/dashboard')}
        role="button"
        tabIndex={0}
        onKeyDown={e => e.key === 'Enter' && navigate('/dashboard')}
        aria-label="Go to dashboard"
      >
        <div className="navbar-logo">
          <Shield size={16} strokeWidth={2.0} />
        </div>
        <div className="navbar-brand-text">
          <span className="navbar-product">INCIDENTIQ</span>
          <span className="navbar-tagline">AI Incident Response</span>
        </div>
      </div>

      {/* Center — Navigation */}
      <ul className="navbar-nav" role="menubar">
        <li role="none">
          <NavLink
            to="/dashboard"
            className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
            role="menuitem"
            id="nav-dashboard"
          >
            Dashboard
          </NavLink>
        </li>
        <li role="none">
          <NavLink
            to="/investigate"
            className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
            role="menuitem"
            id="nav-investigate"
          >
            Investigate
          </NavLink>
        </li>
        <li role="none">
          <NavLink
            to="/reports"
            className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
            role="menuitem"
            id="nav-reports"
          >
            Reports
          </NavLink>
        </li>
      </ul>

      {/* Right — AI Status */}
      <div className="navbar-status">
        <div className="ai-online-pill">
          <span className="ai-live-dot" />
          AI Online
        </div>
      </div>
    </nav>
  )
}
