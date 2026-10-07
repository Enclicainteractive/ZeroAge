'use strict';

const crypto = require('crypto');

function canonicalStatus(userId, age) {
  return JSON.stringify({
    userId: String(userId || ''),
    status: age?.status || '',
    accessClass: age?.accessClass || '',
    region: age?.region || '',
    countryCode: age?.countryCode || null,
    method: age?.method || '',
    issuer: age?.issuer || '',
    verifiedAt: age?.verifiedAt || '',
    expiresAt: age?.expiresAt || ''
  });
}

function signAgeStatus(userId, age, key) {
  if (Buffer.byteLength(String(key || ''), 'utf8') < 32) throw new Error('Age status HMAC key must contain at least 32 bytes');
  return crypto.createHmac('sha256', key).update(canonicalStatus(userId, age)).digest('base64url');
}

function verifyAgeStatus(userId, age, key) {
  if (typeof age?.integrity !== 'string' || Buffer.byteLength(String(key || ''), 'utf8') < 32) return false;
  let expected;
  try { expected = Buffer.from(signAgeStatus(userId, age, key), 'base64url'); } catch (_) { return false; }
  const actual = Buffer.from(age.integrity, 'base64url');
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

module.exports = { signAgeStatus, verifyAgeStatus };
