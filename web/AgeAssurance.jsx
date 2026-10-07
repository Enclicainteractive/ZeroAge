import { useCallback, useEffect, useState } from 'react';
import { getToken, request } from './src/api.js';

const unwrap = (body) => body?.data?.data ?? body?.data ?? body;

function Panel({ children }) {
  return <section className="ei-card mx-auto mt-8 w-full max-w-2xl p-6 sm:p-8">{children}</section>;
}

export default function AgeAssurance() {
  const [isAuthenticated] = useState(() => Boolean(getToken()));
  const fragment = new URLSearchParams(window.location.hash.replace(/^#/, ''));
  const challengeId = fragment.get('id');
  const pairingSecret = fragment.get('secret');
  const providerCandidate = fragment.get('provider') || '';
  let providerUrl = '';
  try { const parsedProvider = new URL(providerCandidate); if (parsedProvider.protocol === 'https:') providerUrl = parsedProvider.toString(); } catch { /* issuer not configured */ }
  const [status, setStatus] = useState(null);
  const [challenge, setChallenge] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const refreshStatus = useCallback(async (signal) => {
    if (!isAuthenticated || challengeId) return null;
    const response = await request('/api/auth/age-assurance/status', 'GET', null, signal);
    const next = unwrap(response);
    setStatus(next);
    return next;
  }, [isAuthenticated, challengeId]);

  useEffect(() => {
    const controller = new AbortController();
    refreshStatus(controller.signal).catch((err) => {
      if (!controller.signal.aborted && err?.code !== 'ERR_CANCELED') setError('Age assurance status is temporarily unavailable.');
    });
    return () => controller.abort();
  }, [refreshStatus]);

  useEffect(() => {
    if (!isAuthenticated || !challenge || challengeId) return undefined;
    let active = true;
    const poll = async () => {
      try {
        const response = await request('/api/auth/age-assurance/status');
        const next = unwrap(response);
        if (active) {
          setStatus(next);
          if (next.status === 'verified') setChallenge(null);
        }
      } catch { /* preserve the last known display; the server remains authoritative */ }
    };
    const timer = window.setInterval(poll, 3000);
    return () => { active = false; window.clearInterval(timer); };
  }, [isAuthenticated, challenge, challengeId]);

  const begin = async () => {
    setBusy(true);
    setError('');
    try {
      const response = await request('/api/auth/age-assurance/challenge', 'POST', {});
      setChallenge(unwrap(response));
    } catch (err) {
      setError(err?.response?.data?.error || 'Could not create a verification session. Please try again.');
    } finally {
      setBusy(false);
    }
  };

  if (challengeId && pairingSecret) {
    return (
      <main className="ei-container py-12">
        <Panel>
          <h1 className="ei-h1 mt-3">Continue on this phone</h1>
          <p className="ei-muted mt-4 max-w-prose text-sm leading-6">
            This one-time handoff is bound to the account that opened the QR code. ZeroAge accepts an age-only assertion signed by a configured trusted issuer. This page does not ask for or upload a government ID, document image, face scan, or date of birth.
          </p>
          <div className="mt-6 rounded-none border border-[var(--border)] p-4 text-sm leading-6">
            <strong>Continue with a trusted issuer</strong>
            <p className="ei-muted mt-2">The issuer receives a one-time challenge and returns a signed age-over-18 result. ZeroAge does not send identity documents or biometrics.</p>
            {providerUrl ? <a className="ei-btn-primary mt-4 inline-flex min-h-[44px] items-center px-4" href={providerUrl} target="_blank" rel="noreferrer">Open trusted age issuer</a>
              : <p className="ei-muted mt-3 text-sm">This deployment has no issuer authorization URL configured.</p>}
          </div>
          <a className="ei-btn-ghost mt-6 inline-flex min-h-[44px] items-center px-4" href="/">Return</a>
        </Panel>
      </main>
    );
  }

  if (!isAuthenticated) {
    return (
      <main className="ei-container py-12">
        <Panel>
          <h1 className="ei-h1 mt-3">Age verification</h1>
          <p className="ei-muted mt-4 text-sm leading-6">Sign in to view your account’s age-assurance status. Verification is only required where the administrator has enabled the policy for your region.</p>
          <a className="ei-btn-primary mt-6 inline-flex min-h-[44px] items-center px-4" href={import.meta.env.VITE_ZEROAGE_LOGIN_URL || '/login'}>Sign in</a>
        </Panel>
      </main>
    );
  }

  return (
    <main className="ei-container py-12">
      <Panel>
        <h1 className="ei-h1 mt-3">Age verification</h1>
        <p className="ei-muted mt-3 text-sm leading-6">Only an age-over-18 result, issuer name, verification time, and expiry are retained. Documents, biometric templates, and date of birth are not accepted by this service.</p>

        {error && <p className="mt-5 border border-[var(--c-shutdown)] p-3 text-sm" role="alert">{error}</p>}
        {status?.status === 'verified' ? (
          <div className="mt-6 border border-[var(--c-sec)] p-4" role="status">
            <h2 className="font-display font-bold">Verified</h2>
            <p className="ei-muted mt-2 text-sm">CoreVR access is enabled for this account. The server checks this status on every protected request.</p>
            {status.verifiedAt && <p className="ei-muted mt-2 text-xs">Verified {new Date(status.verifiedAt).toLocaleDateString()}</p>}
          </div>
        ) : status?.required ? (
          <>
            <div className="mt-6 border border-[var(--c-accent,#f59e0b)] p-4">
              <h2 className="font-display font-bold">Verification required</h2>
              <p className="ei-muted mt-2 text-sm leading-6">CoreVR remains unavailable until the server receives a valid, single-use signed assertion from a configured trusted age issuer. Your account is marked as teen-restricted while verification is pending.</p>
            </div>
            {challenge ? (
              <div className="mt-6 grid gap-5 sm:grid-cols-[180px_1fr] sm:items-center">
                {challenge.qrCodeDataUrl && <img className="mx-auto h-44 w-44 border border-[var(--border)] bg-white p-2" src={challenge.qrCodeDataUrl} alt="One-time ZeroAge verification QR code" />}
                <div>
                  <p className="text-sm font-semibold">Scan with your phone</p>
                  <p className="ei-muted mt-2 text-sm leading-6">This temporary QR code expires in {Math.ceil((challenge.expiresInSeconds || 300) / 60)} minutes and can be used once.</p>
                  {challenge.verificationUrl && <a className="mt-3 inline-block break-all text-xs underline" href={challenge.verificationUrl}>Open the secure verification link</a>}
                  <button className="ei-btn-ghost mt-4 block min-h-[44px] px-4" type="button" onClick={() => setChallenge(null)}>Cancel session</button>
                </div>
              </div>
            ) : (
              <button className="ei-btn-primary mt-6 min-h-[44px] px-5" type="button" disabled={busy} onClick={begin}>
                {busy ? 'Preparing secure session…' : 'Start private verification'}
              </button>
            )}
          </>
        ) : (
          <div className="mt-6 border border-[var(--border)] p-4" role="status">
            <h2 className="font-display font-bold">No verification required</h2>
            <p className="ei-muted mt-2 text-sm">Age verification is not currently required for this account’s region.</p>
            {status?.optionalVerificationAllowed && <button className="ei-btn-ghost mt-4 min-h-[44px] px-4" type="button" disabled={busy} onClick={begin}>{busy ? 'Preparing secure session…' : 'Verify voluntarily with ZeroAge'}</button>}
          </div>
        )}
        <a className="ei-muted mt-6 inline-flex min-h-[44px] items-center text-sm underline" href={import.meta.env.VITE_ZEROAGE_DASHBOARD_URL || '/dashboard'}>Return to dashboard</a>
      </Panel>
    </main>
  );
}
