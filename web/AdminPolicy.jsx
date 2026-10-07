import { useCallback, useEffect, useState } from 'react';
import { getToken, request } from './src/api.js';

const FLAGS = [
  'enabled', 'requireEU', 'requireUK', 'requireUSStates', 'signupGate', 'blockCoreVR', 'blockRealtime', 'dashboardNotice',
  'qrHandoff', 'signedIssuerAssertions', 'bindChallengeToAccount', 'requireChallengeNonce', 'allowNationalEid',
  'allowThirdPartyCredentials', 'allowLocalDocumentScan', 'allowLocalFaceEstimate', 'allowSelfieLiveness', 'requireLiveness',
  'requireDocumentProof', 'allowAgeEstimation', 'allowManualReview', 'allowAppeals', 'allowAlternativeMethods',
  'allowCrossRegionVerification', 'storeRawDocuments', 'storeBiometrics', 'storeDateOfBirth', 'storeExactAge',
  'requireAdultThreshold', 'requireReverification', 'enforceHttps', 'auditOutcomeOnly', 'strictUnknownLocation',
  'enforceApi', 'enforceRealtime', 'adminPanel', 'accessibilityAlternative'
];
const UNSUPPORTED = new Set(['allowLocalDocumentScan', 'allowLocalFaceEstimate', 'allowSelfieLiveness', 'requireLiveness', 'requireDocumentProof', 'allowAgeEstimation', 'storeRawDocuments', 'storeBiometrics', 'storeDateOfBirth', 'storeExactAge']);
const LOCKED = new Set(['signedIssuerAssertions', 'bindChallengeToAccount', 'requireChallengeNonce', 'auditOutcomeOnly', 'enforceHttps', 'blockCoreVR', 'blockRealtime', 'signupGate', 'dashboardNotice', 'qrHandoff', 'enforceApi', 'enforceRealtime', 'requireAdultThreshold', ...UNSUPPORTED]);
const COUNTRIES = ['AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR', 'DE', 'GR', 'HU', 'IE', 'IT', 'LV', 'LT', 'LU', 'MT', 'NL', 'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE', 'GB', 'US-CA', 'US-CO', 'US-CT', 'US-DE', 'US-FL', 'US-GA', 'US-IL', 'US-LA', 'US-MD', 'US-MN', 'US-MS', 'US-MO', 'US-NE', 'US-NJ', 'US-NY', 'US-OH', 'US-OK', 'US-OR', 'US-TN', 'US-TX', 'US-UT', 'US-VA'];
const label = (value) => value.replace(/([A-Z])/g, ' $1').replace(/^./, (c) => c.toUpperCase());
const unwrap = (result) => result?.data?.data ?? result?.data ?? result;

export default function AdminPolicy() {
  const authenticated = Boolean(getToken());
  const [policy, setPolicy] = useState(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  const load = useCallback(async (signal) => {
    setLoading(true);
    setError('');
    try { setPolicy(unwrap(await request('/api/admin/age-assurance-policy', 'GET', null, signal))); }
    catch (err) { if (!signal?.aborted) setError(err.message || 'Could not load age policy.'); }
    finally { if (!signal?.aborted) setLoading(false); }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    if (authenticated) load(controller.signal);
    else setLoading(false);
    return () => controller.abort();
  }, [authenticated, load]);

  const updateFlag = (name, value) => setPolicy((current) => ({
    ...current,
    ...(name === 'enabled' ? { enabled: value } : { flags: { ...current.flags, [name]: value } })
  }));
  const updateRegion = (region, key, value) => setPolicy((current) => ({
    ...current,
    regions: { ...current.regions, [region]: { ...current.regions[region], [key]: value, minimumAge: 18 } },
    flags: region === 'EU' ? { ...current.flags, requireEU: key === 'required' ? value : (key === 'enabled' && !value ? false : current.flags.requireEU) }
      : region === 'GB' ? { ...current.flags, requireUK: key === 'required' ? value : current.flags.requireUK }
        : region === 'US' ? { ...current.flags, requireUSStates: key === 'required' ? value : current.flags.requireUSStates }
          : current.flags
  }));
  const updateCountry = (code, required) => setPolicy((current) => ({
    ...current,
    countries: { ...current.countries, [code]: { enabled: true, required, minimumAge: 18 } }
  }));
  const clearCountry = (code) => setPolicy((current) => {
    const countries = { ...current.countries };
    delete countries[code];
    return { ...current, countries };
  });

  const save = async () => {
    setSaving(true);
    setError('');
    setNotice('');
    try {
      setPolicy(unwrap(await request('/api/admin/age-assurance-policy', 'PUT', { policy })));
      setNotice('Policy saved. Server enforcement updates immediately.');
    } catch (err) { setError(err.message || 'Policy could not be saved.'); }
    finally { setSaving(false); }
  };

  return (
    <main className="ei-container py-12">
      <section className="ei-card mx-auto w-full max-w-5xl p-5 sm:p-8">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div><h1 className="ei-h1">ZeroAge policy</h1><p className="ei-muted mt-3 max-w-[70ch] text-sm leading-6">Age-assurance rollout and country targeting. Saved to the server database; CoreVR decisions are enforced server-side.</p></div>
          {authenticated && <div className="flex gap-2"><button className="ei-btn-ghost min-h-[44px]" disabled={loading || saving} onClick={() => load()}>Reload</button><button className="ei-btn-primary min-h-[44px]" disabled={!policy || loading || saving} onClick={save}>{saving ? 'Saving…' : 'Save policy'}</button></div>}
        </div>
        {!authenticated ? <div className="mt-6 border border-[var(--border)] p-4"><p className="ei-muted text-sm">Sign in with an administrator account to manage ZeroAge.</p><a className="ei-btn-primary mt-4 inline-flex min-h-[44px] items-center" href={import.meta.env.VITE_ZEROAGE_LOGIN_URL || '/login'}>Sign in</a></div>
          : loading ? <p className="ei-muted mt-6" role="status">Loading policy…</p>
            : error ? <p className="mt-6 text-sm text-[var(--c-shutdown)]" role="alert">{error}</p>
              : policy && <>
                {notice && <p className="mt-4 text-sm" role="status">{notice}</p>}
                <label className="mt-6 flex min-h-[52px] items-center gap-3 border border-[var(--border)] p-4 font-semibold"><input type="checkbox" checked={policy.enabled} onChange={(event) => updateFlag('enabled', event.target.checked)} />Enable ZeroAge rollout</label>
                <p className="ei-muted ml-7 mt-1 text-sm">When off, age checks and account region storage are inactive.</p>
                <h2 className="mt-7 font-display text-lg font-bold">Region rules</h2>
                <div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                  {['EU', 'GB', 'US', 'OTHER', 'UNKNOWN'].map((region) => <section key={region} className="border border-[var(--border)] p-4">
                    <h3 className="font-semibold">{region === 'EU' ? 'European Union' : region === 'GB' ? 'United Kingdom' : region === 'US' ? 'United States' : region === 'OTHER' ? 'Other known countries' : 'Unknown location'}</h3>
                    <label className="mt-3 flex min-h-[40px] items-center gap-2 text-sm"><input type="checkbox" checked={policy.regions?.[region]?.enabled === true} onChange={(e) => updateRegion(region, 'enabled', e.target.checked)} />Policy enabled</label>
                    <label className="flex min-h-[40px] items-center gap-2 text-sm"><input type="checkbox" checked={policy.regions?.[region]?.required === true} onChange={(e) => updateRegion(region, 'required', e.target.checked)} />Require verification</label>
                  </section>)}
                </div>
                <details className="mt-4 border border-[var(--border)] p-4">
                  <summary className="cursor-pointer font-semibold">Country and state overrides</summary>
                  <p className="ei-muted mt-2 text-sm">Select a listed EU country or US state. Unconfigured locations inherit region rules.</p>
                  <div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">{COUNTRIES.map((code) => {
                    const current = policy.countries?.[code];
                    const region = code.startsWith('US-') ? 'US' : code === 'GB' ? 'GB' : 'EU';
                    const flag = region === 'EU' ? policy.flags.requireEU : region === 'GB' ? policy.flags.requireUK : policy.flags.requireUSStates;
                    const checked = current ? current.enabled && current.required : policy.regions?.[region]?.enabled && policy.regions?.[region]?.required && flag;
                    return <div key={code} className="flex min-h-[42px] items-center gap-2 border border-[var(--border)] px-3 text-xs"><label className="flex min-h-[40px] flex-1 items-center gap-2"><input type="checkbox" checked={!!checked} onChange={(e) => updateCountry(code, e.target.checked)} /><code>{code}</code></label>{current && <button className="ei-muted underline" type="button" onClick={() => clearCountry(code)}>Reset</button>}</div>;
                  })}</div>
                </details>
                <h2 className="mt-7 font-display text-lg font-bold">Feature flags ({FLAGS.length})</h2>
                <p className="ei-muted mt-1 max-w-[72ch] text-sm leading-6">Sensitive document and facial-processing methods are unavailable and hard-disabled. Other reserved capability flags do not activate an unsupported verifier.</p>
                <div className="mt-3 grid gap-2 sm:grid-cols-2">{FLAGS.filter((name) => name !== 'enabled').map((name) => {
                  const locked = LOCKED.has(name);
                  return <label key={name} className={`flex min-h-[46px] items-center gap-3 border border-[var(--border)] p-3 text-sm ${locked ? 'opacity-70' : 'cursor-pointer'}`}>
                    <input type="checkbox" checked={policy.flags?.[name] === true} disabled={locked} onChange={(e) => updateFlag(name, e.target.checked)} />
                    <span><span className="block font-medium">{label(name)}</span>{locked && <span className="ei-muted text-xs">{UNSUPPORTED.has(name) ? 'Unavailable and hard-disabled' : 'Security invariant'}</span>}</span>
                  </label>;
                })}</div>
              </>}
      </section>
    </main>
  );
}
