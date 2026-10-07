# ZeroAge

ZeroAge is an independently deployable, auditable age-assurance reference implementation. Its web client and server are self-contained under `web/` and `server/`; all runtime dependencies are declared in this project.

## Privacy boundary

- ZeroAge accepts only a short-lived, account-bound, single-use challenge and an Ed25519-signed `ageOver18: true` assertion from a configured issuer.
- Government documents, document images, face images, biometric templates, date of birth, and exact age are not accepted as assertion fields and are never written to the database.
- The durable account record is limited to the outcome (`required`/`verified`), adult access class, broad region/country code for policy evaluation, method, issuer ID, verification time, expiry, and an account-bound HMAC integrity tag. Short-lived challenge records are kept in Redis with a five-minute default TTL.
- The QR handoff puts its one-time secret in a URL fragment. Browsers do not send fragments in HTTP requests or `Referer` headers. Reverse proxies must still be configured not to log response bodies or fragment-bearing client-side URLs.
- Local face estimation, liveness, OCR/document scanning, and AI age inference are deliberately hard-disabled. This repository does not contain a validated local model or a biometric verification implementation; toggling an admin flag cannot enable one.

The server is the authority. It verifies issuer signatures, challenge/account binding, nonce, expiry, single-use consumption, and a separate server-side HMAC over the persisted outcome. The HMAC key is not stored in the database. A frontend boolean or locally stored “verified” value has no authority; editing a status row invalidates its tag.

## Issuer assertion

The age issuer receives the QR payload (`challengeId`, `pairingSecret`, `nonce`, requested threshold and expiry) and submits this shape to `POST /api/auth/age-assurance/complete`:

```json
{
  "challengeId": "...",
  "pairingSecret": "...",
  "assertion": {
    "issuer": "configured-issuer-id",
    "challengeId": "...",
    "nonce": "...",
    "ageOver18": true,
    "issuedAt": "2030-01-01T12:00:00.000Z",
    "expiresAt": "2030-01-01T12:04:00.000Z",
    "signature": "base64url-ed25519-signature"
  }
}
```

The signature is Ed25519 over UTF-8 `JSON.stringify` of the following object in exactly this property order: `issuer`, `challengeId`, `nonce`, `ageOver18`, `issuedAt`, `expiresAt`. Assertions expire within five minutes. The endpoint rejects extra fields, rejects any age-false result, and does not persist the assertion or signature. An issuer must be independently assessed and explicitly configured; the repository does not claim that an unconfigured deployment performs real age verification.

## Run

Requirements: Node.js 20+, MariaDB with the platform-compatible `users` (`legal_json`), `site_settings`, and `revoked_tokens` tables, plus Redis. Place this project behind TLS; do not expose the database, Redis, JWT signing secret, or issuer private key to the web client.

```sh
cp .env.example .env
npm install
npm --prefix web install
npm run build:web
npm test
npm run start:server
```

The server uses `ZEROAGE_JWT_SECRET` to verify access tokens and checks the account row and revocation table. Configure an Ed25519 **public** key and issuer ID; the issuer's private key stays with the issuer. Set `AGE_ASSURANCE_STATUS_HMAC_KEY` to a separate random secret of at least 32 bytes and share it only with services that enforce age status. `ZEROAGE_PUBLIC_ORIGIN` must be the HTTPS web origin. The standalone web app can use `VITE_ZEROAGE_API_URL` when the API is hosted on another origin.

Country and US subdivision data is accepted only when the trusted gateway secret matches `ZEROAGE_GATEWAY_SECRET`. The upstream proxy must strip client-supplied `x-country-code` values before adding verified GeoIP headers. Unknown locations fail closed when the rollout is enabled unless an administrator changes that policy.

## API surface

- `GET /api/auth/age-assurance/status` — authenticated account status.
- `POST /api/auth/age-assurance/challenge` — authenticated challenge creation and QR/link response.
- `POST /api/auth/age-assurance/complete` — issuer-only signed assertion completion; rate limited.
- `GET /api/admin/age-assurance-policy` / `PUT /api/admin/age-assurance-policy` — administrator policy and country overrides.
- `GET /health` — liveness.

The standalone web app serves account verification at `/` and the administrator flag/country configuration at `/admin`. The policy has 37 named feature flags, EU-default targeting once the master switch is enabled, opt-in UK/US rules and per-country/state overrides. Raw-data storage and local biometric/document methods remain hard-disabled regardless of database values.

## Source layout

- `server/` — standalone service, policy rules, Redis challenge protocol and signed-assertion verifier.
- `web/` — independent Vite/React UI used by the standalone project.

The web and service integration layers are intentionally duplicated so this project can be audited and deployed without source imports from another application. Keep their public assertion format and security behavior in sync when changing the protocol.

License: MIT. See `LICENSE`.
