'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { createAgeAssuranceService } = require('./ageAssuranceService');
const policy = require('./policy');
const { verifyAgeStatus } = require('./ageAssuranceIntegrity');

test('regional defaults distinguish EU, opt-in UK/US and unknown locations', () => {
  const enabled = { enabled: true };
  assert.equal(policy.stateForRegistration(enabled, 'DE').accessClass, 'teen');
  assert.equal(policy.stateForRegistration(enabled, 'GB').status, 'not_required');
  assert.equal(policy.stateForRegistration(enabled, 'US-CA').status, 'not_required');
  assert.equal(policy.stateForRegistration(enabled, 'CA').status, 'not_required');
  assert.equal(policy.stateForRegistration(enabled, '').status, 'required');
  assert.equal(policy.stateForRegistration({ enabled: false }, 'DE').countryCode, null);
});

test('signed issuer completion is account-bound, one-use, and stores only minimal status', async () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
  const records = new Map();
  const redis = {
    status: 'ready',
    async set(key, value) { if (records.has(key)) return null; records.set(key, value); return 'OK'; },
    async get(key) { return records.get(key) || null; },
    async del(key) { return records.delete(key) ? 1 : 0; },
    async eval(_script, _keyCount, key) { const value = records.get(key) || null; records.delete(key); return value; }
  };
  let saved;
  const User = { async findByIdAndUpdate(id, update) { saved = { id, update }; return { _id: id }; } };
  const issuerId = 'zeroage-test-issuer';
  const statusHmacKey = 'zeroage-test-status-hmac-key-32-bytes-minimum';
  const service = createAgeAssuranceService({
    query: async () => [{ value: JSON.stringify({ enabled: true }) }],
    redis,
    User,
    fromTrustedGateway: () => true,
    issuerPublicKey: publicKeyPem,
    issuerId,
    issuerAuthorizationUrl: 'https://issuer.example.test/verify',
    statusHmacKey,
    publicOrigin: 'https://zeroage.example.test'
  });
  const challenge = await service.createChallenge({
    _id: 'account-123',
    legal: { ageAssurance: { status: 'required', accessClass: 'teen', countryCode: 'DE' } }
  }, { headers: { 'x-country-code': 'DE' } });
  const qrFragment = new URLSearchParams(new URL(challenge.verificationUrl).hash.slice(1));
  const assertion = {
    issuer: issuerId,
    challengeId: challenge.challengeId,
    nonce: challenge.nonce,
    ageOver18: true,
    issuedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 120_000).toISOString()
  };
  assertion.signature = crypto.sign(null, Buffer.from(JSON.stringify(assertion)), privateKey).toString('base64url');
  const result = await service.completeChallenge({ challengeId: challenge.challengeId, pairingSecret: qrFragment.get('secret'), assertion });
  assert.equal(result.status, 'verified');
  assert.equal(saved.id, 'account-123');
  const durableAge = saved.update.$set['legal.ageAssurance'];
  assert.equal(durableAge.status, 'verified');
  assert.equal(durableAge.accessClass, 'adult');
  assert.deepEqual(Object.keys(durableAge).sort(), ['accessClass', 'countryCode', 'expiresAt', 'integrity', 'issuer', 'method', 'region', 'status', 'verifiedAt'].sort());
  assert.equal(verifyAgeStatus('account-123', durableAge, statusHmacKey), true);
  assert.equal(verifyAgeStatus('different-account', durableAge, statusHmacKey), false);
  await assert.rejects(
    service.completeChallenge({ challengeId: challenge.challengeId, pairingSecret: qrFragment.get('secret'), assertion }),
    (error) => error.code === 'AGE_CHALLENGE_EXPIRED'
  );
});

test('assertion endpoint rejects extra identity fields', async () => {
  const { publicKey } = crypto.generateKeyPairSync('ed25519');
  const service = createAgeAssuranceService({
    query: async () => [{ value: JSON.stringify({ enabled: true }) }],
    redis: { status: 'ready' }, User: {}, fromTrustedGateway: () => true,
    issuerPublicKey: publicKey.export({ type: 'spki', format: 'pem' }),
    issuerId: 'issuer', issuerAuthorizationUrl: 'https://issuer.example.test',
    statusHmacKey: 'zeroage-test-status-hmac-key-32-bytes-minimum', publicOrigin: 'https://zeroage.example.test'
  });
  await assert.rejects(
    service.completeChallenge({ challengeId: 'a'.repeat(24), pairingSecret: 's'.repeat(32), dateOfBirth: '2000-01-01', assertion: {} }),
    (error) => error.code === 'AGE_ASSERTION_FIELDS_INVALID'
  );
});
