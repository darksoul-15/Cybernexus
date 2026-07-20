import { useState, type FormEvent } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { api } from '../api';
import { PasswordField } from '../components/PasswordField';

export function ResetPasswordPage() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const token = params.get('token') ?? '';
  const [password, setPassword] = useState('');
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await api.resetPassword(token, password);
      setDone(true);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  if (!token) {
    return (
      <div className="center-screen">
        <div className="card auth-card">
          <h1 className="brand">
            CYBERNEXUS<span className="brand-x">X</span>
          </h1>
          <div className="error">This reset link is missing its token.</div>
          <p className="hint muted">
            <Link to="/forgot-password">Request a new reset link</Link>
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="center-screen">
      <form className="card auth-card" onSubmit={submit}>
        <h1 className="brand">
          CYBERNEXUS<span className="brand-x">X</span>
        </h1>
        <p className="muted">Choose a new password</p>

        {done ? (
          <>
            <div className="ingest-summary">Password updated. You can now sign in.</div>
            <button type="button" className="btn primary" onClick={() => navigate('/login')}>
              Go to sign in
            </button>
          </>
        ) : (
          <>
            <PasswordField id="new-password" label="New password" value={password} onChange={setPassword} autoComplete="new-password" />
            {error && <div className="error">{error}</div>}
            <button className="btn primary" disabled={busy} type="submit">
              {busy ? '…' : 'Reset password'}
            </button>
          </>
        )}
      </form>
    </div>
  );
}
