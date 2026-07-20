import { Navigate, Route, Routes } from 'react-router-dom';
import { useAuth } from './auth';
import { LoginPage } from './pages/LoginPage';
import { ForgotPasswordPage } from './pages/ForgotPasswordPage';
import { ResetPasswordPage } from './pages/ResetPasswordPage';
import { DashboardPage } from './pages/DashboardPage';
import { ScanningPage } from './pages/ScanningPage';
import { ThreatsPage } from './pages/ThreatsPage';
import { AiAnalystPage } from './pages/AiAnalystPage';
import { IncidentsPage } from './pages/IncidentsPage';
import { EvidencePage } from './pages/EvidencePage';
import { CompliancePage } from './pages/CompliancePage';

export function App() {
  const { user, loading } = useAuth();

  if (loading) {
    return <div className="center-screen">Loading…</div>;
  }

  if (!user) {
    return (
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/forgot-password" element={<ForgotPasswordPage />} />
        <Route path="/reset-password" element={<ResetPasswordPage />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    );
  }

  return (
    <Routes>
      <Route path="/login" element={<Navigate to="/" replace />} />
      <Route path="/forgot-password" element={<Navigate to="/" replace />} />
      <Route path="/reset-password" element={<ResetPasswordPage />} />
      <Route path="/" element={<DashboardPage />} />
      <Route path="/scanning" element={<ScanningPage />} />
      <Route path="/threats" element={<ThreatsPage />} />
      <Route path="/ai" element={<AiAnalystPage />} />
      <Route path="/incidents" element={<IncidentsPage />} />
      <Route path="/evidence" element={<EvidencePage />} />
      <Route
        path="/compliance"
        element={user.role === 'admin' ? <CompliancePage /> : <Navigate to="/" replace />}
      />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
