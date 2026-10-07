'use strict';

const crypto = require('crypto');
const policyTools = require('./policy');
const { signAgeStatus, verifyAgeStatus } = require('./ageAssuranceIntegrity');

const SETTINGS_KEY = 'zeroage_policy';
const CHALLENGE_PREFIX = 'zeroage:challenge:';

function parseStored(value) {
  if (!value) return null;
  if (typeof value === 'object') return value;
  try { return JSON.parse(value); } catch (_) { return null; }
}

function countryFromTrustedGateway(req, fromTrustedGateway) {
  if (!fromTrustedGateway(req)) return '';
  const country = String(req.headers['x-country-code'] || '').trim().toUpperCase();
  const subdivision = String(req.headers['x-region-code'] || '').trim().toUpperCase();
  if (country === 'US') return /^[A-Z]{2}$/.test(subdivision) ? `US-${subdivision}` : 'US';
  return /^[A-Z]{2}$/.test(country) ? country : '';
}

function createAgeAssuranceService({ query, redis, User, fromTrustedGateway, issuerPublicKey, issuerId, issuerAuthorizationUrl, statusHmacKey, publicOrigin }) {
  if (typeof query !== 'function' || !User) throw new TypeError('Age assurance requires database query and User model');

  async function getPolicy() {
    const rows = await query('SELECT value FROM site_settings WHERE key_name = ? LIMIT 1', [SETTINGS_KEY]);
    return policyTools.mergePolicy(parseStored(rows?.[0]?.value));
  }

  function country(req) {
    return countryFromTrustedGateway(req, fromTrustedGateway);
  }
  const isTrustedAgeRecord = (userId, age) => verifyAgeStatus(userId, age, statusHmacKey);
  const isVerified = (userId, age) => policyTools.isVerified(age) && verifyAgeStatus(userId, age, statusHmacKey);

  async function registrationState(req) {
    return policyTools.stateForRegistration(await getPolicy(), country(req));
  }

  async function accountStatus(user, req) {
    const policy = await getPolicy();
    const storedAge = user?.legal?.ageAssurance || null;
    const integrityFailed = policy.enabled && !!storedAge && !isTrustedAgeRecord(user?._id || user?.id, storedAge);
    let stored = integrityFailed ? null : storedAge;
    const trustedCountry = country(req);
    if (!integrityFailed && policy.enabled && trustedCountry && user?._id && !isVerified(user._id, stored) &&
        (!stored?.countryCode || policyTools.isRequired(policy, trustedCountry))) {
      const initialState = policyTools.stateForRegistration(policy, trustedCountry);
      stored = { ...stored, ...initialState };
      stored.integrity = signAgeStatus(user._id, stored, statusHmacKey);
      await User.findByIdAndUpdate(user._id, { $set: { 'legal.ageAssurance': stored } }, { new: true });
    }
    const countryCode = stored?.countryCode || trustedCountry;
    const required = integrityFailed || policyTools.isRequired(policy, countryCode) || policyTools.isRequired(policy, trustedCountry);
    const verified = isVerified(user?._id || user?.id, stored);
    return {
      enabled: policy.enabled,
      showNotice: policy.flags.dashboardNotice,
      optionalVerificationAllowed: policy.enabled && policy.flags.allowCrossRegionVerification,
      statusIntegrityFailed: integrityFailed,
      required,
      status: verified ? 'verified' : (required ? 'required' : 'not_required'),
      accessClass: required && !verified ? 'teen' : (verified ? 'adult' : 'standard'),
      region: stored?.region || policyTools.regionForCountry(countryCode),
      verifiedAt: verified ? stored.verifiedAt || null : null,
      issuer: verified ? stored.issuer || null : null,
      validityDays: policy.verificationValidityDays
    };
  }

  function assertVerifierConfigured() {
    if (!issuerPublicKey || !issuerId || !issuerAuthorizationUrl) {
      const error = new Error('ZeroAge trusted issuer is not configured');
      error.status = 503;
      error.code = 'AGE_ISSUER_UNAVAILABLE';
      throw error;
    }
    if (Buffer.byteLength(String(statusHmacKey || ''), 'utf8') < 32) {
      const error = new Error('ZeroAge status-integrity key is not configured');
      error.status = 503;
      error.code = 'AGE_STATUS_KEY_UNAVAILABLE';
      throw error;
    }
    try { if (new URL(issuerAuthorizationUrl).protocol !== 'https:') throw new Error('HTTPS required'); }
    catch (_) {
      const error = new Error('ZeroAge issuer authorization URL must be HTTPS');
      error.status = 503; error.code = 'AGE_ISSUER_URL_INVALID'; throw error;
    }
    try {
      if (crypto.createPublicKey(issuerPublicKey).asymmetricKeyType !== 'ed25519') throw new Error('unsupported key type');
    } catch (_) {
      const error = new Error('ZeroAge issuer key must be a valid Ed25519 public key');
      error.status = 503;
      error.code = 'AGE_ISSUER_KEY_INVALID';
      throw error;
    }
    if (!redis || redis.status !== 'ready') {
      const error = new Error('ZeroAge challenge storage is unavailable');
      error.status = 503;
      error.code = 'AGE_CHALLENGE_STORAGE_UNAVAILABLE';
      throw error;
    }
  }

  async function createChallenge(user, req) {
    const policy = await getPolicy();
    if (!policy.enabled) {
      const error = new Error('ZeroAge is not enabled for this deployment');
      error.status = 409; error.code = 'AGE_VERIFICATION_DISABLED'; throw error;
    }
    const storedAge = user?.legal?.ageAssurance;
    const trustedAge = isTrustedAgeRecord(user?._id || user?.id, storedAge) ? storedAge : null;
    const location = country(req) || trustedAge?.countryCode || '';
    if (!policyTools.isRequired(policy, location) && !policy.flags.allowCrossRegionVerification) {
      const error = new Error('Age verification is not required for this account');
      error.status = 409;
      error.code = 'AGE_VERIFICATION_NOT_REQUIRED';
      throw error;
    }
    if (isVerified(user?._id || user?.id, trustedAge)) {
      const error = new Error('This account is already age verified');
      error.status = 409;
      error.code = 'AGE_ALREADY_VERIFIED';
      throw error;
    }
    assertVerifierConfigured();

    const challengeId = crypto.randomBytes(18).toString('base64url');
    const pairingSecret = crypto.randomBytes(32).toString('base64url');
    const nonce = crypto.randomBytes(32).toString('base64url');
    const ttl = policy.challengeLifetimeSeconds;
    const record = JSON.stringify({
      userId: String(user._id || user.id),
      secretHash: crypto.createHash('sha256').update(pairingSecret).digest('hex'),
      nonce,
      countryCode: location,
      expiresAt: Date.now() + ttl * 1000
    });
    const saved = await redis.set(`${CHALLENGE_PREFIX}${challengeId}`, record, 'EX', ttl, 'NX');
    if (saved !== 'OK') {
      const error = new Error('Unable to create a single-use verification challenge');
      error.status = 503;
      error.code = 'AGE_CHALLENGE_CREATE_FAILED';
      throw error;
    }

    const origin = String(publicOrigin || '').replace(/\/$/, '');
    if (!origin.startsWith('https://')) {
      const error = new Error('ZeroAge public HTTPS origin is not configured');
      error.status = 503;
      error.code = 'AGE_HTTPS_REQUIRED';
      await redis.del(`${CHALLENGE_PREFIX}${challengeId}`);
      throw error;
    }
    // Put bearer material in the URL fragment. Browsers never send fragments
    // in HTTP requests or Referer headers, keeping it out of access logs.
    let providerUrl = '';
    if (issuerAuthorizationUrl) {
      try {
        const issuerUrl = new URL(issuerAuthorizationUrl);
        if (issuerUrl.protocol !== 'https:') throw new Error('HTTPS required');
        const providerPayload = Buffer.from(JSON.stringify({ challengeId, pairingSecret, nonce, issuer: issuerId, ageOver18: true, expiresAt: new Date(Date.now() + ttl * 1000).toISOString() })).toString('base64url');
        issuerUrl.hash = `zeroage=${providerPayload}`;
        providerUrl = issuerUrl.toString();
      } catch (_) {
        const error = new Error('ZeroAge issuer authorization URL must be HTTPS');
        error.status = 503; error.code = 'AGE_ISSUER_URL_INVALID'; throw error;
      }
    }
    const verificationUrl = `${origin}/zeroage/verify#id=${encodeURIComponent(challengeId)}&secret=${encodeURIComponent(pairingSecret)}&nonce=${encodeURIComponent(nonce)}&provider=${encodeURIComponent(providerUrl)}`;
    let qrCodeDataUrl = null;
    try {
      qrCodeDataUrl = await require('qrcode').toDataURL(verificationUrl, {
        errorCorrectionLevel: 'M', margin: 2, width: 280
      });
    } catch (_) { /* link remains usable if optional QR generation fails */ }
    return { challengeId, nonce, requestedAgeThreshold: 18, verificationUrl, providerUrl, qrCodeDataUrl, expiresInSeconds: ttl };
  }

  function assertionPayload(assertion) {
    return JSON.stringify({
      issuer: assertion.issuer,
      challengeId: assertion.challengeId,
      nonce: assertion.nonce,
      ageOver18: assertion.ageOver18,
      issuedAt: assertion.issuedAt,
      expiresAt: assertion.expiresAt
    });
  }

  async function completeChallenge(body) {
    assertVerifierConfigured();
    const challengeId = String(body?.challengeId || '');
    const pairingSecret = String(body?.pairingSecret || '');
    const assertion = body?.assertion;
    if (!/^[A-Za-z0-9_-]{20,64}$/.test(challengeId) || pairingSecret.length < 32 || !assertion || typeof assertion !== 'object') {
      const error = new Error('Invalid ZeroAge challenge response');
      error.status = 400;
      error.code = 'AGE_ASSERTION_INVALID';
      throw error;
    }
    const allowedBodyKeys = new Set(['challengeId', 'pairingSecret', 'assertion']);
    const allowedAssertionKeys = new Set(['issuer', 'challengeId', 'nonce', 'ageOver18', 'issuedAt', 'expiresAt', 'signature']);
    if (Object.keys(body || {}).some((key) => !allowedBodyKeys.has(key)) ||
        Object.keys(assertion).some((key) => !allowedAssertionKeys.has(key)) ||
        String(assertion.signature || '').length > 256 || String(assertion.issuer || '').length > 160) {
      const error = new Error('Only the minimal age assertion fields are accepted');
      error.status = 400;
      error.code = 'AGE_ASSERTION_FIELDS_INVALID';
      throw error;
    }

    const key = `${CHALLENGE_PREFIX}${challengeId}`;
    const recordRaw = await redis.get(key);
    if (!recordRaw) {
      const error = new Error('Verification challenge expired or already used');
      error.status = 410;
      error.code = 'AGE_CHALLENGE_EXPIRED';
      throw error;
    }
    const record = parseStored(recordRaw);
    const providedHash = crypto.createHash('sha256').update(pairingSecret).digest('hex');
    const expectedHash = Buffer.from(String(record?.secretHash || ''), 'hex');
    const actualHash = Buffer.from(providedHash, 'hex');
    if (expectedHash.length !== actualHash.length || !crypto.timingSafeEqual(expectedHash, actualHash)) {
      const error = new Error('Verification challenge pairing failed');
      error.status = 403;
      error.code = 'AGE_PAIRING_INVALID';
      throw error;
    }
    if (assertion.issuer !== issuerId || assertion.challengeId !== challengeId ||
        assertion.nonce !== record.nonce || assertion.ageOver18 !== true ||
        typeof assertion.signature !== 'string') {
      const error = new Error('Trusted issuer assertion does not match this challenge');
      error.status = 400;
      error.code = 'AGE_ASSERTION_INVALID';
      throw error;
    }
    const now = Date.now();
    const issuedAt = new Date(assertion.issuedAt).getTime();
    const expiresAt = new Date(assertion.expiresAt).getTime();
    if (!Number.isFinite(issuedAt) || !Number.isFinite(expiresAt) || issuedAt > now + 60_000 ||
        expiresAt <= now || expiresAt - issuedAt > 5 * 60_000) {
      const error = new Error('Trusted issuer assertion is expired or outside the allowed time window');
      error.status = 400;
      error.code = 'AGE_ASSERTION_EXPIRED';
      throw error;
    }
    let signature;
    try { signature = Buffer.from(assertion.signature, 'base64url'); } catch (_) { signature = Buffer.alloc(0); }
    let valid = false;
    try {
      valid = crypto.verify(null, Buffer.from(assertionPayload(assertion)), issuerPublicKey, signature);
    } catch (_) { valid = false; }
    if (!valid) {
      const error = new Error('Trusted issuer signature is invalid');
      error.status = 403;
      error.code = 'AGE_SIGNATURE_INVALID';
      throw error;
    }

    // Redis GET+DEL is not atomic by itself. Use Lua so a challenge cannot be
    // completed twice by concurrent requests, then persist only the outcome.
    const consumed = await redis.eval(
      "local v=redis.call('GET',KEYS[1]); if not v then return nil end; redis.call('DEL',KEYS[1]); return v",
      1, key
    );
    if (!consumed) {
      const error = new Error('Verification challenge expired or already used');
      error.status = 410;
      error.code = 'AGE_CHALLENGE_EXPIRED';
      throw error;
    }
    const consumedRecord = parseStored(consumed);
    const consumedHash = Buffer.from(String(consumedRecord?.secretHash || ''), 'hex');
    if (consumedRecord?.userId !== record.userId || consumedRecord?.nonce !== record.nonce ||
        consumedHash.length !== actualHash.length || !crypto.timingSafeEqual(consumedHash, actualHash)) {
      const error = new Error('Verification challenge binding changed');
      error.status = 409;
      error.code = 'AGE_CHALLENGE_BINDING_INVALID';
      throw error;
    }

    const policy = await getPolicy();
    const verifiedAt = new Date().toISOString();
    const expires = new Date(Date.now() + policy.verificationValidityDays * 86400_000).toISOString();
    const verifiedAge = {
      status: 'verified',
      accessClass: 'adult',
      region: policyTools.regionForCountry(consumedRecord.countryCode),
      countryCode: consumedRecord.countryCode || null,
      method: 'signed_issuer_assertion',
      issuer: issuerId,
      verifiedAt,
      expiresAt: expires
    };
    verifiedAge.integrity = signAgeStatus(consumedRecord.userId, verifiedAge, statusHmacKey);
    const user = await User.findByIdAndUpdate(consumedRecord.userId, { $set: { 'legal.ageAssurance': verifiedAge } }, { new: true });
    if (!user) {
      const error = new Error('Account no longer exists');
      error.status = 404;
      error.code = 'ACCOUNT_NOT_FOUND';
      throw error;
    }
    return { status: 'verified', accessClass: 'adult', verifiedAt, expiresAt: expires };
  }

  return { getPolicy, country, registrationState, accountStatus, createChallenge, completeChallenge };
}

module.exports = { createAgeAssuranceService, SETTINGS_KEY };
