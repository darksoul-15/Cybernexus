import type { ReactNode } from 'react';
import { NavLink } from 'react-router-dom';
import { useAuth } from '../auth';

/** Shared top bar: brand, primary nav, page-specific actions, user + logout. */
export function TopNav({ children }: { children?: ReactNode }) {
  const { user, logout } = useAuth();
  const linkClass = ({ isActive }: { isActive: boolean }) => (isActive ? 'nav-link active' : 'nav-link');

  return (
    <header className="topbar">
      <div className="topbar-left">
        <div className="brand small">
          CYBERNEXUS<span className="brand-x">X</span>
        </div>
        <nav className="nav">
          <NavLink to="/" end className={linkClass}>Dashboard</NavLink>
          <NavLink to="/scanning" className={linkClass}>Scanning</NavLink>
          <NavLink to="/threats" className={linkClass}>Threats</NavLink>
          <NavLink to="/incidents" className={linkClass}>Incidents</NavLink>
          <NavLink to="/evidence" className={linkClass}>Evidence</NavLink>
          {user?.role === 'admin' && <NavLink to="/compliance" className={linkClass}>Compliance</NavLink>}
        </nav>
      </div>
      <div className="topbar-right">
        {children}
        <span className="muted">{user?.email} · {user?.role}</span>
        <button className="btn ghost" onClick={logout}>Sign out</button>
      </div>
    </header>
  );
}
