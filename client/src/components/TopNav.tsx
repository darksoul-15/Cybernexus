import type { ReactNode, SVGProps } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import { useAuth } from '../auth';

/** Lucide-style inline icons (stroke, currentColor) — no emoji per design rules. */
const ico = (props: SVGProps<SVGSVGElement>): SVGProps<SVGSVGElement> => ({
  className: 'nav-ico', viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor',
  strokeWidth: 1.8, strokeLinecap: 'round', strokeLinejoin: 'round', 'aria-hidden': true, ...props,
});

const IconDashboard = () => (
  <svg {...ico({})}><rect x="3" y="3" width="7" height="7" rx="1.5" /><rect x="14" y="3" width="7" height="7" rx="1.5" /><rect x="14" y="14" width="7" height="7" rx="1.5" /><rect x="3" y="14" width="7" height="7" rx="1.5" /></svg>
);
const IconScan = () => (
  <svg {...ico({})}><path d="M4 7V5a1 1 0 0 1 1-1h2M17 4h2a1 1 0 0 1 1 1v2M20 17v2a1 1 0 0 1-1 1h-2M7 20H5a1 1 0 0 1-1-1v-2" /><path d="M4 12h16" /></svg>
);
const IconThreat = () => (
  <svg {...ico({})}><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z" /><path d="M12 8v4" /><path d="M12 16h.01" /></svg>
);
const IconIncident = () => (
  <svg {...ico({})}><path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9" /><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0" /></svg>
);
const IconEvidence = () => (
  <svg {...ico({})}><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z" /><path d="m9 12 2 2 4-4" /></svg>
);
const IconReport = () => (
  <svg {...ico({})}><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z" /><path d="M14 2v6h6" /><path d="M8 13h8M8 17h8M8 9h2" /></svg>
);
const IconSpark = () => (
  <svg {...ico({ className: undefined })} width="18" height="18"><path d="M12 3v4M12 17v4M3 12h4M17 12h4" /><path d="M12 8a4 4 0 0 0 0 8 4 4 0 0 0 0-8Z" /></svg>
);

/** Route → human page title, shown in the main-column header. */
const TITLES: Record<string, string> = {
  '/': 'SOC Dashboard',
  '/scanning': 'Vulnerability Scanning',
  '/threats': 'Threat Detection',
  '/incidents': 'Incident Response',
  '/evidence': 'Evidence Vault',
  '/compliance': 'Compliance & Reports',
};

/**
 * App chrome: a fixed left sidebar (brand + grouped nav + promo) plus an in-flow
 * page header in the main column that carries the page title, per-page action
 * `children`, and the signed-in user. Pages keep rendering `<TopNav>…</TopNav>`.
 */
export function TopNav({ children }: { children?: ReactNode }) {
  const { user, logout } = useAuth();
  const { pathname } = useLocation();
  const linkClass = ({ isActive }: { isActive: boolean }) => (isActive ? 'nav-link active' : 'nav-link');
  const title = TITLES[pathname] ?? 'CYBERNEXUS X';
  const initial = (user?.email?.[0] ?? '?').toUpperCase();

  return (
    <>
      <aside className="sidebar">
        <div className="side-brand">
          <div className="side-logo">C</div>
          <div className="brand small">CYBERNEXUS<span className="brand-x">X</span></div>
        </div>

        <div className="side-section">Monitor</div>
        <nav className="nav vertical">
          <NavLink to="/" end className={linkClass}><IconDashboard />Dashboard</NavLink>
          <NavLink to="/scanning" className={linkClass}><IconScan />Scanning</NavLink>
          <NavLink to="/threats" className={linkClass}><IconThreat />Threats</NavLink>
        </nav>

        <div className="side-section">Respond</div>
        <nav className="nav vertical">
          <NavLink to="/incidents" className={linkClass}><IconIncident />Incidents</NavLink>
          <NavLink to="/evidence" className={linkClass}><IconEvidence />Evidence</NavLink>
        </nav>

        {user?.role === 'admin' && (
          <>
            <div className="side-section">Tools</div>
            <nav className="nav vertical">
              <NavLink to="/compliance" className={linkClass}><IconReport />Compliance</NavLink>
            </nav>
          </>
        )}

        <div className="side-spacer" />

        <div className="promo-card">
          <div className="promo-icon"><IconSpark /></div>
          <p className="promo-title">Live SOC monitoring</p>
          <p className="promo-text">Scans stay localhost-scoped. Every metric traces to a real database record.</p>
        </div>
      </aside>

      <header className="page-header">
        <h1 className="page-title">{title}</h1>
        <div className="page-header-right">
          {children}
          <span className="user-chip">
            <span className="avatar">{initial}</span>
            {user?.email} · {user?.role}
          </span>
          <button className="btn ghost sm" onClick={logout}>Sign out</button>
        </div>
      </header>
    </>
  );
}
