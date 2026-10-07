'use strict';

require('dotenv').config();
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const Redis = require('ioredis');
const { createAgeAssuranceService } = require('./ageAssuranceService');
const { mergePolicy, FLAG_NAMES, EU_COUNTRIES, US_STATES } = require('./policy');

const app = express();
app.set('trust proxy', Number(process.env.ZEROAGE_TRUST_PROXY_HOPS) || 1);
app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], imgSrc: ["'self'", 'data:'], styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'], fontSrc: ["'self'", 'https://fonts.gstatic.com'], scriptSrc: ["'self'"] } } }));
app.use(express.json({ limit: '16kb', strict: true }));
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store');
  res.set('Pragma', 'no-cache');
  next();
});

const origins = String(process.env.ZEROAGE_CORS_ORIGINS || '').split(',').map((item) => item.trim()).filter(Boolean);
app.use((req, res, next) => {
  const origin = req.get('origin');
  if (origin && !origins.includes(origin)) return res.status(403).json({ error: 'Origin not allowed', code: 'CORS_DENIED' });
  if (origin) {
    res.set('Access-Control-Allow-Origin', origin);
    res.set('Vary', 'Origin');
    res.set('Access-Control-Allow-Credentials', 'true');
  }
  if (req.method === 'OPTIONS') {
    res.set('Access-Control-Allow-Methods', 'GET,POST,PUT,OPTIONS');
    res.set('Access-Control-Allow-Headers', 'Authorization,Content-Type');
    return res.sendStatus(204);
  }
  return next();
});

const pool = mysql.createPool({
  host: process.env.MARIADB_HOST || '127.0.0.1',
  port: Number(process.env.MARIADB_PORT) || 3306,
  user: process.env.MARIADB_USER,
  password: process.env.MARIADB_PASSWORD,
  database: process.env.MARIADB_DATABASE,
  waitForConnections: true,
  connectionLimit: 10,
  charset: 'utf8mb4',
  timezone: 'Z'
});
const redis = new Redis({
  host: process.env.REDIS_HOST || '127.0.0.1',
  port: Number(process.env.REDIS_PORT) || 6379,
  password: process.env.REDIS_PASSWORD || undefined,
  lazyConnect: false,
  enableReadyCheck: true,
  maxRetriesPerRequest: 2
});
const query = async (sql, params = []) => {
  const [rows] = await pool.query(sql, params);
  return rows;
};
const User = {
  async findByIdAndUpdate(id, update) {
    const rows = await query('SELECT legal_json FROM users WHERE id = ? LIMIT 1', [String(id)]);
    if (!rows[0]) return null;
    let legal = {};
    try { legal = JSON.parse(rows[0].legal_json || '{}'); } catch (_) { legal = {}; }
    legal.ageAssurance = update?.$set?.['legal.ageAssurance'];
    await query('UPDATE users SET legal_json = ?, updated_at = NOW() WHERE id = ?', [JSON.stringify(legal), String(id)]);
    return { _id: String(id), id: String(id), legal };
  }
};

function sameSecret(left, right) {
  const a = Buffer.from(String(left || ''));
  const b = Buffer.from(String(right || ''));
  return a.length === b.length && a.length > 0 && crypto.timingSafeEqual(a, b);
}
function fromTrustedGateway(req) {
  return sameSecret(req.get('x-zeroage-gateway-key'), process.env.ZEROAGE_GATEWAY_SECRET);
}
async function authenticate(req, res, next) {
  const match = String(req.get('authorization') || '').match(/^Bearer\s+(.+)$/i);
  if (!match || !process.env.ZEROAGE_JWT_SECRET) return res.status(401).json({ error: 'Authentication required', code: 'TOKEN_MISSING' });
  try {
    const payload = jwt.verify(match[1], process.env.ZEROAGE_JWT_SECRET, { algorithms: ['HS256'] });
    const userId = payload.userId || payload.sub;
    if (!userId || payload.type !== 'access' || !payload.jti) return res.status(401).json({ error: 'Invalid access token', code: 'TOKEN_INVALID' });
    const [users, revoked] = await Promise.all([
      query('SELECT id, role, status, legal_json FROM users WHERE id = ? LIMIT 1', [String(userId)]),
      query('SELECT id FROM revoked_tokens WHERE jti = ? LIMIT 1', [String(payload.jti)])
    ]);
    if (revoked?.length) return res.status(401).json({ error: 'Access token revoked', code: 'TOKEN_REVOKED' });
    const row = users[0];
    if (!row) return res.status(401).json({ error: 'Account not found', code: 'ACCOUNT_NOT_FOUND' });
    if (row.status === 'banned') return res.status(403).json({ error: 'Account is unavailable', code: 'ACCOUNT_BANNED' });
    let legal = {};
    try { legal = JSON.parse(row.legal_json || '{}'); } catch (_) { legal = {}; }
    req.user = { _id: String(userId), id: String(userId), role: row.role || 'user', legal };
    return next();
  } catch (_) { return res.status(401).json({ error: 'Invalid access token', code: 'TOKEN_INVALID' }); }
}
function requireAdmin(req, res, next) {
  if (!['admin', 'superadmin', 'owner'].includes(req.user?.role)) return res.status(403).json({ error: 'Administrator access required', code: 'FORBIDDEN' });
  return next();
}

const issuerPublicKey = String(process.env.AGE_ASSURANCE_ISSUER_PUBLIC_KEY || '').replace(/\\n/g, '\n');
const ageService = createAgeAssuranceService({
  query, redis, User, fromTrustedGateway,
  issuerPublicKey: issuerPublicKey || null,
  issuerId: process.env.AGE_ASSURANCE_ISSUER_ID || '',
  issuerAuthorizationUrl: process.env.AGE_ASSURANCE_ISSUER_AUTH_URL || '',
  statusHmacKey: process.env.AGE_ASSURANCE_STATUS_HMAC_KEY || '',
  publicOrigin: process.env.ZEROAGE_PUBLIC_ORIGIN || ''
});
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many verification attempts', code: 'RATE_LIMITED' } });
const httpsOnly = (req, res, next) => {
  if (process.env.NODE_ENV === 'development' || req.secure) return next();
  return res.status(400).json({ error: 'HTTPS is required', code: 'HTTPS_REQUIRED' });
};

app.get('/health', (_req, res) => res.json({ status: 'ok', service: 'zeroage', version: 1 }));
app.get('/api/auth/age-assurance/status', httpsOnly, authenticate, async (req, res) => {
  try { return res.json({ success: true, data: await ageService.accountStatus(req.user, req) }); }
  catch (_) { return res.status(503).json({ error: 'Age status temporarily unavailable', code: 'AGE_STATUS_UNAVAILABLE' }); }
});
app.post('/api/auth/age-assurance/challenge', httpsOnly, authenticate, limiter, async (req, res) => {
  try { return res.status(201).json({ success: true, data: await ageService.createChallenge(req.user, req) }); }
  catch (error) { return res.status(error.status || 503).json({ error: error.message, code: error.code || 'AGE_CHALLENGE_FAILED' }); }
});
app.post('/api/auth/age-assurance/complete', httpsOnly, limiter, async (req, res) => {
  try { return res.json({ success: true, data: await ageService.completeChallenge(req.body) }); }
  catch (error) { return res.status(error.status || 400).json({ error: error.message, code: error.code || 'AGE_ASSERTION_FAILED' }); }
});

app.get('/api/admin/age-assurance-policy', authenticate, requireAdmin, async (_req, res) => {
  try {
    const rows = await query('SELECT value FROM site_settings WHERE key_name = ? LIMIT 1', ['zeroage_policy']);
    return res.json({ success: true, data: mergePolicy(rows[0]?.value || null) });
  } catch (_) { return res.status(503).json({ error: 'Policy unavailable', code: 'AGE_POLICY_UNAVAILABLE' }); }
});
app.put('/api/admin/age-assurance-policy', authenticate, requireAdmin, limiter, async (req, res) => {
  const input = req.body?.policy;
  const countriesAllowed = new Set([...EU_COUNTRIES, 'GB', ...US_STATES]);
  if (!input || typeof input !== 'object' || Array.isArray(input) || typeof input.enabled !== 'boolean' ||
      Object.entries(input.flags || {}).some(([name, value]) => !FLAG_NAMES.includes(name) || typeof value !== 'boolean') ||
      Object.entries(input.countries || {}).some(([code, rule]) => !countriesAllowed.has(code) || typeof rule?.enabled !== 'boolean' || typeof rule?.required !== 'boolean')) {
    return res.status(400).json({ error: 'Invalid ZeroAge policy', code: 'AGE_POLICY_INVALID' });
  }
  try {
    const policy = mergePolicy(input);
    await query(`INSERT INTO site_settings (key_name, value, description, updated_by) VALUES (?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE value=VALUES(value), description=VALUES(description), updated_by=VALUES(updated_by), updated_at=NOW()`,
    ['zeroage_policy', JSON.stringify(policy), 'ZeroAge age assurance rollout and country policy', req.user.id]);
    return res.json({ success: true, data: policy });
  } catch (_) { return res.status(503).json({ error: 'Policy could not be saved', code: 'AGE_POLICY_SAVE_FAILED' }); }
});

const webBuild = path.resolve(__dirname, '../web/dist');
app.use(express.static(webBuild, { index: false, maxAge: '1h' }));
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  return res.sendFile(path.join(webBuild, 'index.html'), (error) => error && next(error));
});
app.use((err, _req, res, _next) => {
  // Keep assertion bodies, signatures, and pairing secrets out of logs.
  res.status(500).json({ error: 'Internal ZeroAge error', code: 'INTERNAL_ERROR' });
});

const port = Number(process.env.ZEROAGE_PORT) || 3088;
const server = app.listen(port, () => console.info(`ZeroAge listening on port ${port}`));
async function shutdown() {
  server.close();
  await Promise.allSettled([pool.end(), redis.quit()]);
  process.exit(0);
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

module.exports = app;
