import { useState, type FormEvent } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api';

export function ForgotPasswordPage() {
  const [email, setEmail] = useState('');
  const [result, setResult] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const res = await api.forgotPassword(email);
      setResult(res.message);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="center-screen">
      <form className="card auth-card" onSubmit={submit}>
        <h1 className="brand">
          CYBERNEXUS<span className="brand-x">X</span>
        </h1>
        <p className="muted">Reset your password</p>

        {result ? (
          <div className="ingest-summary">{result}</div>
        ) : (
          <>
            <label htmlFor="fp-email">
              Email
              <input id="fp-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
            </label>
            {error && <div className="error">{error}</div>}
            <button className="btn primary" disabled={busy} type="submit">
              {busy ? '…' : 'Send reset link'}
            </button>
          </>
        )}

        <p className="hint muted">
          <Link to="/login">Back to sign in</Link>
        </p>
      </form>
    </div>
  );
}
