'use strict';

// ZeroAge policy is intentionally data-only. Verification decisions are made
// by the API from a trusted, signed issuer assertion; browser state is never
// considered proof of age.
const EU_COUNTRIES = [
  'AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR', 'DE', 'GR', 'HU',
  'IE', 'IT', 'LV', 'LT', 'LU', 'MT', 'NL', 'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE'
];

const US_STATES = [
  'US-CA', 'US-CO', 'US-CT', 'US-DE', 'US-FL', 'US-GA', 'US-IL', 'US-LA',
  'US-MD', 'US-MN', 'US-MS', 'US-MO', 'US-NE', 'US-NJ', 'US-NY', 'US-OH',
  'US-OK', 'US-OR', 'US-TN', 'US-TX', 'US-UT', 'US-VA'
];

const FLAG_NAMES = [
  'enabled', 'requireEU', 'requireUK', 'requireUSStates', 'signupGate', 'blockCoreVR',
  'blockRealtime', 'dashboardNotice', 'qrHandoff', 'signedIssuerAssertions',
  'bindChallengeToAccount', 'requireChallengeNonce', 'allowNationalEid',
  'allowThirdPartyCredentials', 'allowLocalDocumentScan', 'allowLocalFaceEstimate',
  'allowSelfieLiveness', 'requireLiveness', 'requireDocumentProof', 'allowAgeEstimation',
  'allowManualReview', 'allowAppeals', 'allowAlternativeMethods', 'allowCrossRegionVerification', 'storeRawDocuments',
  'storeBiometrics', 'storeDateOfBirth', 'storeExactAge', 'requireAdultThreshold',
  'requireReverification', 'enforceHttps', 'auditOutcomeOnly', 'strictUnknownLocation',
  'enforceApi', 'enforceRealtime', 'adminPanel', 'accessibilityAlternative'
];

// Privacy/security invariants are fixed on, not operator choices. EU is the
// default target when the master rollout is enabled; UK and US remain opt-in.
const DEFAULT_FLAGS = Object.freeze(Object.fromEntries(FLAG_NAMES.map((name) => [name,
  ['signedIssuerAssertions', 'bindChallengeToAccount', 'requireChallengeNonce', 'auditOutcomeOnly', 'enforceHttps',
    'blockCoreVR', 'blockRealtime', 'signupGate', 'dashboardNotice', 'qrHandoff', 'enforceApi', 'enforceRealtime'].includes(name)
    ? true
    : name === 'requireEU'
      ? true
    : name === 'strictUnknownLocation'
        ? true
        : name === 'requireAdultThreshold' || name === 'allowCrossRegionVerification'
          ? true
        : false
])));

const DEFAULT_POLICY = Object.freeze({
  version: 1,
  enabled: false,
  flags: DEFAULT_FLAGS,
  countries: Object.freeze({}),
  regions: Object.freeze({
    EU: Object.freeze({ enabled: true, required: true, minimumAge: 18 }),
    GB: Object.freeze({ enabled: false, required: false, minimumAge: 18 }),
    US: Object.freeze({ enabled: false, required: false, minimumAge: 18 }),
    OTHER: Object.freeze({ enabled: false, required: false, minimumAge: 18 }),
    UNKNOWN: Object.freeze({ enabled: false, required: false, minimumAge: 18 })
  }),
  challengeLifetimeSeconds: 300,
  verificationValidityDays: 365
});

function mergePolicy(input) {
  const source = input && typeof input === 'object' && !Array.isArray(input) ? input : {};
  const flags = { ...DEFAULT_FLAGS };
  if (source.flags && typeof source.flags === 'object') {
    for (const name of FLAG_NAMES) {
      if (typeof source.flags[name] === 'boolean') flags[name] = source.flags[name];
    }
  }
  // Storage of raw identity material is prohibited even if an older or
  // hand-edited settings record tries to enable it.
  flags.storeRawDocuments = false;
  flags.storeBiometrics = false;
  flags.storeDateOfBirth = false;
  flags.storeExactAge = false;
  flags.allowLocalDocumentScan = false;
  flags.allowLocalFaceEstimate = false;
  flags.allowSelfieLiveness = false;
  flags.requireLiveness = false;
  flags.requireDocumentProof = false;
  flags.allowAgeEstimation = false;
  flags.blockCoreVR = true;
  flags.blockRealtime = true;
  flags.signupGate = true;
  flags.dashboardNotice = true;
  flags.qrHandoff = true;
  flags.enforceApi = true;
  flags.enforceRealtime = true;
  flags.requireAdultThreshold = true;
  flags.allowCrossRegionVerification = true;
  flags.signedIssuerAssertions = true;
  flags.bindChallengeToAccount = true;
  flags.requireChallengeNonce = true;
  flags.auditOutcomeOnly = true;
  flags.enforceHttps = true;

  const countries = {};
  if (source.countries && typeof source.countries === 'object' && !Array.isArray(source.countries)) {
    for (const code of [...EU_COUNTRIES, 'GB', ...US_STATES]) {
      const entry = source.countries[code];
      if (!entry || typeof entry !== 'object') continue;
      countries[code] = {
        enabled: entry.enabled === true,
        required: entry.required === true,
        minimumAge: 18
      };
    }
  }
  const regions = {};
  for (const name of ['EU', 'GB', 'US', 'OTHER', 'UNKNOWN']) {
    const entry = source.regions?.[name] || DEFAULT_POLICY.regions[name];
    regions[name] = {
      enabled: entry.enabled === true,
      required: entry.required === true,
      minimumAge: 18
    };
  }
  return {
    version: 1,
    enabled: source.enabled === true,
    flags,
    countries,
    regions,
    challengeLifetimeSeconds: clampInteger(source.challengeLifetimeSeconds, 300, 60, 600),
    verificationValidityDays: clampInteger(source.verificationValidityDays, 365, 1, 730)
  };
}

function clampInteger(value, fallback, min, max) {
  const number = Number(value);
  return Number.isInteger(number) ? Math.max(min, Math.min(max, number)) : fallback;
}

function regionForCountry(countryCode) {
  const code = String(countryCode || '').trim().toUpperCase();
  if (EU_COUNTRIES.includes(code)) return 'EU';
  if (code === 'GB' || code === 'UK') return 'GB';
  if (code.startsWith('US-') || code === 'US') return 'US';
  if (/^[A-Z]{2}$/.test(code)) return 'OTHER';
  return 'UNKNOWN';
}

function isRequired(policyInput, countryCode) {
  const policy = mergePolicy(policyInput);
  if (!policy.enabled) return false;
  const code = String(countryCode || '').trim().toUpperCase();
  const configured = policy.countries[code];
  if (configured) return configured.enabled && configured.required;
  const region = regionForCountry(code);
  if (region === 'EU' && !policy.flags.requireEU) return false;
  if (region === 'GB' && !policy.flags.requireUK) return false;
  if (region === 'US' && !policy.flags.requireUSStates) return false;
  if (region === 'UNKNOWN' && policy.flags.strictUnknownLocation) return true;
  const rule = policy.regions[region];
  return rule.enabled && rule.required;
}

function stateForRegistration(policyInput, countryCode, now = new Date()) {
  const policy = mergePolicy(policyInput);
  const code = String(countryCode || '').trim().toUpperCase();
  if (!isRequired(policy, code)) {
    return { status: 'not_required', accessClass: 'standard', region: policy.enabled ? regionForCountry(code) : 'UNKNOWN', countryCode: policy.enabled ? (code || null) : null };
  }
  return {
    status: 'required',
    accessClass: 'teen',
    region: regionForCountry(code),
    countryCode: code || null,
    updatedAt: now.toISOString()
  };
}

function isVerified(ageAssurance, now = Date.now()) {
  if (!ageAssurance || ageAssurance.status !== 'verified' || ageAssurance.accessClass !== 'adult') return false;
  if (!ageAssurance.expiresAt) return true;
  const expiry = new Date(ageAssurance.expiresAt).getTime();
  return Number.isFinite(expiry) && expiry > now;
}

module.exports = {
  EU_COUNTRIES,
  US_STATES,
  FLAG_NAMES,
  DEFAULT_POLICY,
  DEFAULT_FLAGS,
  mergePolicy,
  regionForCountry,
  isRequired,
  stateForRegistration,
  isVerified
};
