'use strict';

const { isRequired, isVerified, mergePolicy, stateForRegistration } = require('./policy');
const { verifyAgeStatus } = require('./ageAssuranceIntegrity');

function createCoreVRAgeGate({ query, fromTrustedGateway, statusHmacKey = process.env.AGE_ASSURANCE_STATUS_HMAC_KEY || '' }) {
  return async function zeroAgeCoreVRGate(req, res, next) {
    if (!fromTrustedGateway(req)) return next();
    const userId = String(req.headers['x-user-id'] || '');
    if (!userId) return next(); // public catalog endpoints remain public
    try {
      const [users, settings] = await Promise.all([
        query('SELECT legal_json FROM users WHERE id = ? LIMIT 1', [userId]),
        query('SELECT value FROM site_settings WHERE key_name = ? LIMIT 1', ['zeroage_policy'])
      ]);
      if (!users?.[0]) return res.status(401).json({ error: 'Account not found', code: 'ACCOUNT_NOT_FOUND' });
      let legal = {};
      let storedPolicy = null;
      try { legal = JSON.parse(users[0].legal_json || '{}'); } catch (_) { legal = {}; }
      try { storedPolicy = settings?.[0]?.value ? JSON.parse(settings[0].value) : null; } catch (_) { storedPolicy = null; }
      const policy = mergePolicy(storedPolicy);
      const storedAge = legal?.ageAssurance || null;
      if (policy.enabled && storedAge && !verifyAgeStatus(userId, storedAge, statusHmacKey)) {
        return res.status(403).json({ error: 'Age assurance integrity check failed; restart ZeroAge verification', code: 'AGE_STATUS_INTEGRITY_INVALID' });
      }
      let age = verifyAgeStatus(userId, storedAge, statusHmacKey) ? storedAge : null;
      const rawCountry = String(req.headers['x-country-code'] || '').trim().toUpperCase();
      const rawRegion = String(req.headers['x-region-code'] || '').trim().toUpperCase();
      const trustedCountry = rawCountry === 'US' && /^[A-Z]{2}$/.test(rawRegion) ? `US-${rawRegion}` : (/^[A-Z]{2}$/.test(rawCountry) ? rawCountry : '');
      const verified = isVerified(age) && verifyAgeStatus(userId, age, statusHmacKey);
      if (policy.enabled && trustedCountry && !verified && (!age?.countryCode || isRequired(policy, trustedCountry))) {
        age = { ...age, ...stateForRegistration(policy, trustedCountry) };
        legal.ageAssurance = age;
        await query('UPDATE users SET legal_json = ?, updated_at = NOW() WHERE id = ?', [JSON.stringify(legal), userId]);
      }
      const countryCode = age?.countryCode || '';
      if (policy.enabled && policy.flags.blockCoreVR && (isRequired(policy, countryCode) || isRequired(policy, trustedCountry)) && !verified) {
        return res.status(403).json({
          error: 'Complete ZeroAge verification before using CoreVR',
          code: 'AGE_VERIFICATION_REQUIRED',
          data: { status: 'required', accessClass: 'teen', verificationUrl: '/zeroage' }
        });
      }
      if (policy.enabled && policy.flags.strictUnknownLocation && !countryCode && !trustedCountry && !verified) {
        return res.status(403).json({
          error: 'Age assurance is required because account region could not be determined',
          code: 'AGE_REGION_UNKNOWN',
          data: { status: 'required', accessClass: 'teen', verificationUrl: '/zeroage' }
        });
      }
      return next();
    } catch (_) {
      // Do not allow a database/settings outage to silently disable an enabled
      // restriction. Authenticated CoreVR requests fail closed.
      return res.status(503).json({ error: 'Age assurance status temporarily unavailable', code: 'AGE_ASSURANCE_UNAVAILABLE' });
    }
  };
}

module.exports = { createCoreVRAgeGate };
