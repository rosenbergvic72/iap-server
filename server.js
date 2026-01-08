// iap-server/server.js
//
// Google Play Subscription verifier (stable baseline) + Partner access codes (no Google/Apple billing)
//
// Endpoints:
//   GET  /                               health
//   POST /iap/google/subscription/verify  verify Google Play subscription (unchanged response shape)
//   GET  /entitlements?userId=...         compute PRO entitlement (Google is NOT checked here; codes only)
//   POST /redeem/code                     redeem partner code -> grants PRO until accessUntil
//
// Admin (requires x-admin-key == ADMIN_KEY):
//   GET  /admin                           lightweight admin UI
//   POST /admin/codes/generate             generate codes
//   GET  /admin/codes/stats                stats
//   GET  /admin/codes/list                 list latest codes (hashed only)
//   POST /admin/codes/disable              disable a code
//   POST /admin/users/revoke               revoke user's code-based access
//
// Env vars:
//   PORT
//   PACKAGE_NAME                      e.g. com.rosenbergvictor72.pealim2
//   SERVICE_ACCOUNT_JSON              (paste raw JSON key)  OR
//   GOOGLE_APPLICATION_CREDENTIALS    (path to service-account.json)
//   API_KEY                           (optional; if set, client must send x-api-key)
//   ALLOWED_ORIGIN                    (optional; CORS allow-origin; default "*")
//   ACK_ON_VERIFY                     (optional; "1" to auto-ack active subs on verify)
//   ACK_ONLY_IF_ACTIVE                (optional; default "1"; if "0", ack when not active too)
//   ENTITLE_WHILE_NOT_EXPIRED         (optional; default "1"; if "1", pro=true while not expired)
//   ENTITLE_REQUIRE_ACK               (optional; default "0"; if "1", require acknowledged to entitle)
//   ACK_REFRESH_RETRIES               (optional; default "1"; refresh + recheck after ack to avoid client polling)
//   ACK_REFRESH_DELAY_MS              (optional; default "800"; delay between retries)
//
//   // Partner codes (no billing):
//   CODE_PEPPER                       secret string used to hash codes (required for codes)
//   DATABASE_URL                      optional Postgres URL; if absent uses in-memory store (NOT persistent)
//   ADMIN_KEY                         admin key for /admin and /admin/* endpoints
//   CODE_DEFAULT_DAYS                 default days for generated codes (default 30)
//   CODE_DEFAULT_MAX_USES             default max uses for generated codes (default 1)
//
// Notes:
// - Google verification logic below is intentionally very close to your working "server work.js".
// - Partner codes are additive: verify endpoint returns pro=true if Google entitlement OR code-based access.
//
const fs = require('fs');
const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const { google } = require('googleapis');

// Optional Postgres (safe to run without it)
let pg = null;
try { pg = require('pg'); } catch (e) { /* no-op */ }

// ---------- Config ----------
const PORT = process.env.PORT || 10000;
const PACKAGE_NAME = process.env.PACKAGE_NAME || '';
const API_KEY = process.env.API_KEY || '';
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';

const ACK_ON_VERIFY = process.env.ACK_ON_VERIFY === '1';
const ACK_ONLY_IF_ACTIVE = process.env.ACK_ONLY_IF_ACTIVE !== '0';
const ENTITLE_WHILE_NOT_EXPIRED = process.env.ENTITLE_WHILE_NOT_EXPIRED !== '0';
const ENTITLE_REQUIRE_ACK = process.env.ENTITLE_REQUIRE_ACK === '1';

const ACK_REFRESH_RETRIES = Number(process.env.ACK_REFRESH_RETRIES || 1);
const ACK_REFRESH_DELAY_MS = Number(process.env.ACK_REFRESH_DELAY_MS || 800);

const DATABASE_URL = process.env.DATABASE_URL || '';
const CODE_PEPPER = process.env.CODE_PEPPER || '';
const ADMIN_KEY = process.env.ADMIN_KEY || '';
const CODE_DEFAULT_DAYS = Number(process.env.CODE_DEFAULT_DAYS || 30);
const CODE_DEFAULT_MAX_USES = Number(process.env.CODE_DEFAULT_MAX_USES || 1);

const SERVICE_ACCOUNT_JSON = process.env.SERVICE_ACCOUNT_JSON || '';

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ---------- App ----------
const app = express();
app.use(bodyParser.json({ limit: '1mb' }));

// CORS + security-ish headers
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGIN || '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-api-key, x-admin-key');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  if (req.method === 'OPTIONS') return res.status(204).send('');
  next();
});

// Optional API key
app.use((req, res, next) => {
  if (!API_KEY) return next();
  const key = req.headers['x-api-key'];
  if (key !== API_KEY) return res.status(401).json({ ok: false, error: 'unauthorized' });
  next();
});

// ---------- Google auth ----------
function loadServiceAccount() {
  if (SERVICE_ACCOUNT_JSON) {
    try {
      return JSON.parse(SERVICE_ACCOUNT_JSON);
    } catch (e) {
      console.error('[IAP] SERVICE_ACCOUNT_JSON parse error:', e?.message || e);
      throw e;
    }
  }
  const p = process.env.GOOGLE_APPLICATION_CREDENTIALS;
  if (p && fs.existsSync(p)) {
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  }
  throw new Error('Missing SERVICE_ACCOUNT_JSON or GOOGLE_APPLICATION_CREDENTIALS');
}

async function getPlayPublisher() {
  const sa = loadServiceAccount();
  const auth = new google.auth.JWT(
    sa.client_email,
    null,
    sa.private_key,
    ['https://www.googleapis.com/auth/androidpublisher']
  );
  await auth.authorize();
  return google.androidpublisher({ version: 'v3', auth });
}

// ---------- Partner code storage ----------
const mem = {
  codes: new Map(),         // codeHash -> { createdAt, expiresAt, maxUses, uses, note, disabled }
  userAccess: new Map(),    // userId -> { accessUntil, updatedAt, source }
  redemptions: [],          // [{ codeHash, userId, redeemedAt, accessUntil }]
};

const db = {
  enabled: false,
  pool: null,
};

function sha256(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

function codeHash(code) {
  if (!CODE_PEPPER) throw new Error('CODE_PEPPER_not_set');
  return sha256(`${CODE_PEPPER}::${String(code).trim().toUpperCase()}`);
}

function makeCode() {
  // readable: XXXX-XXXX-XXXX
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const chunk = (n) => Array.from({ length: n }, () => alphabet[Math.floor(Math.random() * alphabet.length)]).join('');
  return `${chunk(4)}-${chunk(4)}-${chunk(4)}`;
}

async function initDbIfPossible() {
  if (!DATABASE_URL || !pg) return;
  try {
    db.pool = new pg.Pool({ connectionString: DATABASE_URL, max: 5, idleTimeoutMillis: 30_000 });
    await db.pool.query('SELECT 1');
    db.enabled = true;

    await db.pool.query(`
      CREATE TABLE IF NOT EXISTS access_codes (
        code_hash TEXT PRIMARY KEY,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        expires_at TIMESTAMPTZ NULL,
        max_uses INT NOT NULL DEFAULT 1,
        uses INT NOT NULL DEFAULT 0,
        note TEXT NULL,
        disabled BOOLEAN NOT NULL DEFAULT FALSE
      );
    `);

    await db.pool.query(`
      CREATE TABLE IF NOT EXISTS user_access (
        user_id TEXT PRIMARY KEY,
        access_until TIMESTAMPTZ NOT NULL,
        source TEXT NOT NULL DEFAULT 'code',
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);

    await db.pool.query(`
      CREATE TABLE IF NOT EXISTS redemptions (
        id BIGSERIAL PRIMARY KEY,
        code_hash TEXT NOT NULL,
        user_id TEXT NOT NULL,
        redeemed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        access_until TIMESTAMPTZ NOT NULL
      );
      CREATE INDEX IF NOT EXISTS redemptions_user_idx ON redemptions(user_id);
      CREATE INDEX IF NOT EXISTS redemptions_code_idx ON redemptions(code_hash);
    `);

    console.log('[CODES] Postgres enabled');
  } catch (e) {
    console.warn('[CODES] Postgres disabled (fallback to memory):', e?.message || e);
    db.enabled = false;
    db.pool = null;
  }
}

async function upsertCode(rec) {
  const { code_hash, expires_at, max_uses, note } = rec;
  if (db.enabled) {
    await db.pool.query(
      `INSERT INTO access_codes(code_hash, expires_at, max_uses, note)
       VALUES($1,$2,$3,$4)
       ON CONFLICT(code_hash) DO UPDATE SET expires_at=EXCLUDED.expires_at, max_uses=EXCLUDED.max_uses, note=EXCLUDED.note`,
      [code_hash, expires_at, max_uses, note]
    );
  } else {
    mem.codes.set(code_hash, {
      createdAt: new Date().toISOString(),
      expiresAt: expires_at ? new Date(expires_at).toISOString() : null,
      maxUses: max_uses,
      uses: 0,
      note: note || null,
      disabled: false,
    });
  }
}

async function getCodeRow(code_hash) {
  if (db.enabled) {
    const r = await db.pool.query(`SELECT * FROM access_codes WHERE code_hash=$1`, [code_hash]);
    return r.rows[0] || null;
  }
  const m = mem.codes.get(code_hash);
  if (!m) return null;
  return {
    code_hash,
    created_at: m.createdAt,
    expires_at: m.expiresAt,
    max_uses: m.maxUses,
    uses: m.uses,
    note: m.note,
    disabled: m.disabled,
  };
}

async function incCodeUse(code_hash) {
  if (db.enabled) {
    await db.pool.query(`UPDATE access_codes SET uses = uses + 1 WHERE code_hash=$1`, [code_hash]);
    return;
  }
  const m = mem.codes.get(code_hash);
  if (m) m.uses += 1;
}

async function disableCode(code_hash) {
  if (db.enabled) {
    await db.pool.query(`UPDATE access_codes SET disabled=TRUE WHERE code_hash=$1`, [code_hash]);
    return;
  }
  const m = mem.codes.get(code_hash);
  if (m) m.disabled = true;
}

async function upsertUserAccess(user_id, access_until_iso, source='code') {
  if (db.enabled) {
    await db.pool.query(
      `INSERT INTO user_access(user_id, access_until, source)
       VALUES($1,$2,$3)
       ON CONFLICT(user_id) DO UPDATE SET access_until=GREATEST(user_access.access_until, EXCLUDED.access_until), source=EXCLUDED.source, updated_at=NOW()`,
      [user_id, access_until_iso, source]
    );
    return;
  }
  const prev = mem.userAccess.get(user_id);
  const nextMs = Date.parse(access_until_iso);
  const prevMs = prev ? Date.parse(prev.accessUntil) : 0;
  const accessUntil = (prev && prevMs > nextMs) ? prev.accessUntil : access_until_iso;
  mem.userAccess.set(user_id, { accessUntil, updatedAt: new Date().toISOString(), source });
}

async function getUserAccess(user_id) {
  if (db.enabled) {
    const r = await db.pool.query(`SELECT * FROM user_access WHERE user_id=$1`, [user_id]);
    return r.rows[0] || null;
  }
  const m = mem.userAccess.get(user_id);
  if (!m) return null;
  return { user_id, access_until: m.accessUntil, source: m.source, updated_at: m.updatedAt };
}

async function revokeUser(user_id) {
  if (db.enabled) {
    await db.pool.query(`DELETE FROM user_access WHERE user_id=$1`, [user_id]);
    return;
  }
  mem.userAccess.delete(user_id);
}

async function addRedemption(code_hash, user_id, access_until_iso) {
  if (db.enabled) {
    await db.pool.query(
      `INSERT INTO redemptions(code_hash, user_id, access_until) VALUES($1,$2,$3)`,
      [code_hash, user_id, access_until_iso]
    );
    return;
  }
  mem.redemptions.push({ codeHash: code_hash, userId: user_id, redeemedAt: new Date().toISOString(), accessUntil: access_until_iso });
}

async function getStats() {
  if (db.enabled) {
    const codes = await db.pool.query(`SELECT COUNT(*)::int AS total, SUM(uses)::int AS uses FROM access_codes`);
    const users = await db.pool.query(`SELECT COUNT(*)::int AS users FROM user_access WHERE access_until > NOW()`);
    const last = await db.pool.query(`SELECT redeemed_at, user_id, code_hash, access_until FROM redemptions ORDER BY redeemed_at DESC LIMIT 20`);
    return {
      storage: 'postgres',
      codes: codes.rows[0] || { total: 0, uses: 0 },
      activeUsers: users.rows[0]?.users || 0,
      lastRedemptions: last.rows || [],
    };
  }
  const now = Date.now();
  const activeUsers = Array.from(mem.userAccess.values()).filter(u => Date.parse(u.accessUntil) > now).length;
  const totalCodes = mem.codes.size;
  const uses = Array.from(mem.codes.values()).reduce((a, c) => a + (c.uses || 0), 0);
  const lastRedemptions = mem.redemptions.slice(-20).reverse();
  return { storage: 'memory', codes: { total: totalCodes, uses }, activeUsers, lastRedemptions };
}

// ---------- Helpers: compute code-based entitlement ----------
async function computeCodeEntitlement(userId) {
  if (!userId) return { codeEntitled: false, accessUntil: null };
  const row = await getUserAccess(userId);
  if (!row) return { codeEntitled: false, accessUntil: null };
  const until = row.access_until;
  const ok = Date.parse(until) > Date.now();
  return { codeEntitled: ok, accessUntil: until };
}

// ---------- Health ----------
app.get('/', async (req, res) => {
  const stats = await getStats().catch(() => null);
  res.json({
    ok: true,
    service: 'google-play-iap-verifier+codes',
    package: PACKAGE_NAME || null,
    cors: ALLOWED_ORIGIN || '*',
    ackOnVerify: ACK_ON_VERIFY,
    ackOnlyIfActive: ACK_ONLY_IF_ACTIVE,
    entitleWhileNotExpired: ENTITLE_WHILE_NOT_EXPIRED,
    entitleRequireAck: ENTITLE_REQUIRE_ACK,
    ackRefreshRetries: ACK_REFRESH_RETRIES,
    ackRefreshDelayMs: ACK_REFRESH_DELAY_MS,
    codes: {
      enabled: !!CODE_PEPPER,
      storage: stats?.storage || (DATABASE_URL ? 'postgres?' : 'memory'),
    },
    v: '1.4.0'
  });
});

// ---------- Entitlements (codes only; no Google calls) ----------
app.get('/entitlements', async (req, res) => {
  try {
    const userId = String(req.query.userId || '').trim();
    const code = await computeCodeEntitlement(userId);
    res.json({ ok: true, userId: userId || null, pro: !!code.codeEntitled, source: code.codeEntitled ? 'code' : 'none', accessUntil: code.accessUntil });
  } catch (e) {
    res.status(500).json({ ok: false, error: 'entitlements_failed', message: e?.message || String(e) });
  }
});

// ---------- Redeem code ----------
app.post('/redeem/code', async (req, res) => {
  try {
    const userId = String(req.body?.userId || '').trim();
    const code = String(req.body?.code || '').trim().toUpperCase();
    if (!userId) return res.status(400).json({ ok: false, error: 'missing_userId' });
    if (!code) return res.status(400).json({ ok: false, error: 'missing_code' });
    if (!CODE_PEPPER) return res.status(503).json({ ok: false, error: 'CODE_PEPPER_not_set' });

    const ch = codeHash(code);
    const row = await getCodeRow(ch);
    if (!row) return res.status(404).json({ ok: false, error: 'code_not_found' });
    if (row.disabled) return res.status(403).json({ ok: false, error: 'code_disabled' });

    const now = Date.now();
    const exp = row.expires_at ? Date.parse(row.expires_at) : null;
    if (exp && exp <= now) return res.status(403).json({ ok: false, error: 'code_expired', expiresAt: row.expires_at });

    if (Number(row.uses) >= Number(row.max_uses)) {
      return res.status(403).json({ ok: false, error: 'code_max_uses_reached', maxUses: row.max_uses, uses: row.uses });
    }

    // Grant: if code has expires_at use that date; otherwise default duration from now
    let accessUntilISO = null;
    if (row.expires_at) {
      accessUntilISO = new Date(row.expires_at).toISOString();
    } else {
      const ms = now + CODE_DEFAULT_DAYS * 24 * 60 * 60 * 1000;
      accessUntilISO = new Date(ms).toISOString();
    }

    await incCodeUse(ch);
    await upsertUserAccess(userId, accessUntilISO, 'code');
    await addRedemption(ch, userId, accessUntilISO);

    res.json({ ok: true, userId, pro: true, accessUntil: accessUntilISO });
  } catch (e) {
    res.status(500).json({ ok: false, error: 'redeem_failed', message: e?.message || String(e) });
  }
});

// ---------- Existing Google verify endpoint (kept very close to old) ----------
function isActiveState(v) {
  // Accept both old/v3 and v2-normalized states
  return v === 1 || v === '1' || v === 'ACTIVE' || v === 'SUBSCRIPTION_STATE_ACTIVE';
}

function normalizeV3(sub) {
  // Response from purchases.subscriptions.get (v3)
  const expiryTimeMillis = sub?.expiryTimeMillis ? Number(sub.expiryTimeMillis) : null;
  const notExpired = expiryTimeMillis ? expiryTimeMillis > Date.now() : false;
  const isAcked = sub?.acknowledgementState === 1;
  return {
    api: 'v3',
    purchaseState: sub?.purchaseState,
    acknowledgementState: sub?.acknowledgementState,
    expiryTimeMillis,
    expiresAtISO: expiryTimeMillis ? new Date(expiryTimeMillis).toISOString() : null,
    notExpired,
    isAcked,
  };
}

function normalizeV2(v2) {
  // Response from purchases.subscriptionsv2.get
  const data = v2?.data || v2 || {};
  const lineItems = Array.isArray(data.lineItems) ? data.lineItems : [];
  // take max expiry among line items (important!)
  const expMs = lineItems
    .map(li => li?.expiryTime ? Date.parse(li.expiryTime) : NaN)
    .filter(n => Number.isFinite(n));
  const maxExp = expMs.length ? Math.max(...expMs) : null;

  const ackState = lineItems.map(li => li?.acknowledgementState).find(Boolean) || null;
  const isAcked =
    ackState === 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED' ||
    ackState === 1 || ackState === '1';

  const notExpired = maxExp ? maxExp > Date.now() : false;

  return {
    api: 'v2',
    subscriptionState: data.subscriptionState || null,
    acknowledgementState: ackState,
    expiresAtISO: maxExp ? new Date(maxExp).toISOString() : null,
    notExpired,
    isAcked,
    raw: data,
  };
}

async function tryAck(publisher, pkg, productId, token, active) {
  const ack = { tried: false, ok: false, reason: null };
  if (!ACK_ON_VERIFY) return ack;
  if (ACK_ONLY_IF_ACTIVE && !active) {
    ack.reason = 'skip_not_active';
    return ack;
  }
  ack.tried = true;
  try {
    await publisher.purchases.subscriptions.acknowledge({
      packageName: pkg,
      subscriptionId: productId,
      token,
      requestBody: {},
    });
    ack.ok = true;
    ack.reason = 'acked';
  } catch (e) {
    ack.ok = false;
    ack.reason = 'ack_failed';
    ack.error = e?.message || String(e);
  }
  return ack;
}

app.post('/iap/google/subscription/verify', async (req, res) => {
  try {
    const userId = req.body?.userId || null;
    const productId = req.body?.productId || null;
    const purchaseToken = req.body?.purchaseToken || null;
    const packageName_from_client = req.body?.packageName || null;

    if (!productId || !purchaseToken) {
      return res.status(400).json({ ok: false, error: 'missing_productId_or_purchaseToken' });
    }

    const pkg = PACKAGE_NAME || packageName_from_client || '';
    if (!pkg) return res.status(400).json({ ok: false, error: 'missing_packageName' });

    const publisher = await getPlayPublisher();

    let used = 'v3';
    let normalized = null;

    // Try v3 first (as in old)
    try {
      const sub = await publisher.purchases.subscriptions.get({
        packageName: pkg,
        subscriptionId: productId,
        token: purchaseToken,
      });
      normalized = normalizeV3(sub.data);
      used = 'v3';
    } catch (eV3) {
      // Fallback v2
      try {
        const v2 = await publisher.purchases.subscriptionsv2.get({
          packageName: pkg,
          token: purchaseToken,
        });
        normalized = normalizeV2(v2);
        used = 'v2';
      } catch (eV2) {
        return res.status(400).json({
          ok: false,
          error: 'verify_failed',
          usedVersionTried: ['v3', 'v2'],
          v3: eV3?.message || String(eV3),
          v2: eV2?.message || String(eV2),
        });
      }
    }

    const notExpired = !!normalized.notExpired;
    const active = normalized.api === 'v2'
      ? isActiveState(normalized.subscriptionState)
      : (normalized.purchaseState === 0); // v3 purchaseState 0 = purchased

    const isAcked = !!normalized.isAcked;

    // entitlement from Google
    let entitled = false;
    if (ENTITLE_WHILE_NOT_EXPIRED) {
      entitled = notExpired;
    } else {
      entitled = active;
    }
    if (ENTITLE_REQUIRE_ACK) {
      entitled = entitled && isAcked;
    }

    // ack attempt (only meaningful for v3 endpoint used)
    const ack = await tryAck(publisher, pkg, productId, purchaseToken, active);

    // optional refresh after ack to reduce client polling (old behavior)
    if (ack.ok && ACK_REFRESH_RETRIES > 0) {
      for (let i = 0; i < ACK_REFRESH_RETRIES; i++) {
        await sleep(ACK_REFRESH_DELAY_MS);
        try {
          const sub2 = await publisher.purchases.subscriptions.get({
            packageName: pkg,
            subscriptionId: productId,
            token: purchaseToken,
          });
          const n2 = normalizeV3(sub2.data);
          // update ack state
          normalized.isAcked = n2.isAcked;
          normalized.acknowledgementState = n2.acknowledgementState;
          break;
        } catch (_) { /* ignore */ }
      }
    }

    // Add code-based entitlement
    const code = await computeCodeEntitlement(userId);
    const pro = !!entitled || !!code.codeEntitled;

    return res.json({
      ok: true,
      packageName: pkg,
      userId: userId || null,
      productId: productId || null,
      pro,
      entitled: pro, // keep existing clients happy
      googleEntitled: !!entitled,
      codeEntitled: !!code.codeEntitled,
      codeAccessUntil: code.accessUntil,
      notExpired,
      isAcked: !!normalized.isAcked,
      ack: { tried: ack.tried, ok: ack.ok, reason: ack.reason || null, error: ack.error || null },
      ...normalized,
      usedVersion: used,
    });
  } catch (e) {
    console.error('[IAP][VERIFY][ERROR]', e);
    return res.status(500).json({ ok: false, error: 'server_error', message: e?.message || String(e) });
  }
});

// ---------- Admin auth ----------
function requireAdmin(req, res, next) {
  if (!ADMIN_KEY) return res.status(403).json({ ok: false, error: 'ADMIN_KEY_not_set' });
  const key = String(req.headers['x-admin-key'] || '').trim();
  if (key !== ADMIN_KEY) return res.status(401).json({ ok: false, error: 'bad_admin_key' });
  next();
}

// ---------- Admin endpoints ----------
app.post('/admin/codes/generate', requireAdmin, async (req, res) => {
  try {
    if (!CODE_PEPPER) return res.status(503).json({ ok: false, error: 'CODE_PEPPER_not_set' });

    const count = Math.max(1, Math.min(200, Number(req.body?.count || 10)));
    const days = Number(req.body?.days || CODE_DEFAULT_DAYS);
    const maxUses = Math.max(1, Math.min(1000, Number(req.body?.maxUses || CODE_DEFAULT_MAX_USES)));
    const note = (req.body?.note ? String(req.body.note).slice(0, 200) : null);

    const expiresAt = days > 0 ? new Date(Date.now() + days * 86400000).toISOString() : null;

    const codes = [];
    for (let i = 0; i < count; i++) {
      const c = makeCode();
      const ch = codeHash(c);
      await upsertCode({ code_hash: ch, expires_at: expiresAt, max_uses: maxUses, note });
      codes.push({ code: c, expiresAt, maxUses, note });
    }

    res.json({ ok: true, count: codes.length, codes });
  } catch (e) {
    res.status(500).json({ ok: false, error: 'generate_failed', message: e?.message || String(e) });
  }
});

app.get('/admin/codes/stats', requireAdmin, async (req, res) => {
  try {
    const stats = await getStats();
    res.json({ ok: true, ...stats });
  } catch (e) {
    res.status(500).json({ ok: false, error: 'stats_failed', message: e?.message || String(e) });
  }
});

app.get('/admin/codes/list', requireAdmin, async (req, res) => {
  try {
    const limit = Math.max(1, Math.min(200, Number(req.query.limit || 50)));
    if (db.enabled) {
      const r = await db.pool.query(
        `SELECT code_hash, created_at, expires_at, max_uses, uses, note, disabled
         FROM access_codes ORDER BY created_at DESC LIMIT $1`,
        [limit]
      );
      return res.json({ ok: true, storage: 'postgres', codes: r.rows });
    }
    const rows = Array.from(mem.codes.entries())
      .map(([code_hash, c]) => ({
        code_hash,
        created_at: c.createdAt,
        expires_at: c.expiresAt,
        max_uses: c.maxUses,
        uses: c.uses,
        note: c.note,
        disabled: c.disabled,
      }))
      .sort((a,b) => Date.parse(b.created_at) - Date.parse(a.created_at))
      .slice(0, limit);
    res.json({ ok: true, storage: 'memory', codes: rows });
  } catch (e) {
    res.status(500).json({ ok: false, error: 'list_failed', message: e?.message || String(e) });
  }
});

app.post('/admin/codes/disable', requireAdmin, async (req, res) => {
  try {
    const code = String(req.body?.code || '').trim().toUpperCase();
    const code_hash = String(req.body?.codeHash || '').trim();
    let ch = code_hash;
    if (!ch && code) ch = codeHash(code);
    if (!ch) return res.status(400).json({ ok: false, error: 'missing_code_or_codeHash' });
    await disableCode(ch);
    res.json({ ok: true, disabled: true, codeHash: ch });
  } catch (e) {
    res.status(500).json({ ok: false, error: 'disable_failed', message: e?.message || String(e) });
  }
});

app.post('/admin/users/revoke', requireAdmin, async (req, res) => {
  try {
    const userId = String(req.body?.userId || '').trim();
    if (!userId) return res.status(400).json({ ok: false, error: 'missing_userId' });
    await revokeUser(userId);
    res.json({ ok: true, userId, revoked: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: 'revoke_failed', message: e?.message || String(e) });
  }
});

// ---------- Admin UI (simple, more reliable than the previous one) ----------
app.get('/admin', (req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.end(`<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>IAP Admin</title>
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial; padding:20px; max-width:980px; margin:0 auto;}
    .row{display:flex; gap:12px; flex-wrap:wrap; align-items:flex-end;}
    label{display:block; font-size:12px; opacity:.7; margin-bottom:6px;}
    input,textarea,button{font:inherit; padding:10px 12px; border:1px solid #ddd; border-radius:10px;}
    input{min-width:240px;}
    button{cursor:pointer;}
    .card{border:1px solid #eee; border-radius:16px; padding:16px; margin:14px 0;}
    pre{background:#0b1020; color:#e8eeff; padding:12px; border-radius:12px; overflow:auto;}
    .muted{opacity:.7}
    table{border-collapse:collapse; width:100%;}
    th,td{border-bottom:1px solid #eee; text-align:left; padding:8px;}
    th{font-size:12px; opacity:.7}
    .ok{color:#0a7}
    .bad{color:#d33}
  </style>
</head>
<body>
  <h2>IAP Admin</h2>
  <p class="muted">Авторизация: заголовок <code>x-admin-key</code> должен совпадать с <code>ADMIN_KEY</code> в env.</p>

  <div class="card">
    <div class="row">
      <div>
        <label>ADMIN KEY</label>
        <input id="k" type="password" placeholder="x-admin-key" />
      </div>
      <button id="save">Сохранить</button>
      <button id="clear">Очистить</button>
      <span id="status" class="muted"></span>
    </div>
  </div>

  <div class="card">
    <h3>Сгенерировать коды</h3>
    <div class="row">
      <div><label>Кол-во</label><input id="count" type="number" value="10" /></div>
      <div><label>Дней (0 = без срока)</label><input id="days" type="number" value="${CODE_DEFAULT_DAYS}" /></div>
      <div><label>Max uses</label><input id="maxUses" type="number" value="${CODE_DEFAULT_MAX_USES}" /></div>
      <div style="flex:1; min-width:260px;"><label>Комментарий</label><input id="note" placeholder="например: partner Ulpan X" /></div>
      <button id="gen">Generate</button>
    </div>
    <pre id="genOut" class="muted"></pre>
  </div>

  <div class="card">
    <h3>Статус</h3>
    <div class="row">
      <button id="statsBtn">Refresh stats</button>
      <button id="listBtn">List codes</button>
      <div><label>limit</label><input id="limit" type="number" value="50"/></div>
    </div>
    <pre id="statsOut" class="muted"></pre>
  </div>

  <div class="card">
    <h3>Отключить код</h3>
    <div class="row">
      <div><label>CODE (plain)</label><input id="disableCode" placeholder="XXXX-XXXX-XXXX" /></div>
      <div><label>или CodeHash</label><input id="disableHash" placeholder="sha256..." /></div>
      <button id="disableBtn">Disable</button>
    </div>
    <pre id="disableOut" class="muted"></pre>
  </div>

  <div class="card">
    <h3>Отозвать доступ у userId</h3>
    <div class="row">
      <div><label>userId</label><input id="revokeUser" placeholder="user id" /></div>
      <button id="revokeBtn">Revoke</button>
    </div>
    <pre id="revokeOut" class="muted"></pre>
  </div>

<script>
  const $ = (id) => document.getElementById(id);
  const LS = 'iap_admin_key';

  function getKey(){ return (localStorage.getItem(LS) || '').trim(); }
  function setKey(v){ localStorage.setItem(LS, v.trim()); }
  function clrKey(){ localStorage.removeItem(LS); }

  function setStatus(msg, ok=true){
    const el = $('status');
    el.textContent = msg;
    el.className = ok ? 'ok' : 'bad';
  }

  async function api(path, opts={}){
    const key = getKey();
    const headers = Object.assign(
      {'Content-Type':'application/json'},
      opts.headers || {},
      key ? {'x-admin-key': key} : {}
    );
    const res = await fetch(path, Object.assign({}, opts, {headers}));
    const txt = await res.text();
    let js = null;
    try { js = JSON.parse(txt); } catch(_) { js = { raw: txt }; }
    if (!res.ok) throw Object.assign(new Error(js?.error || res.statusText), { status: res.status, body: js });
    return js;
  }

  function pretty(o){ return JSON.stringify(o, null, 2); }

  $('k').value = getKey();

  $('save').onclick = () => { setKey($('k').value); setStatus('saved'); };
  $('clear').onclick = () => { clrKey(); $('k').value=''; setStatus('cleared'); };

  $('gen').onclick = async () => {
    $('genOut').textContent = '...';
    try{
      const out = await api('/admin/codes/generate', {method:'POST', body: JSON.stringify({
        count: Number($('count').value||10),
        days: Number($('days').value||0),
        maxUses: Number($('maxUses').value||1),
        note: $('note').value || null,
      })});
      $('genOut').textContent = pretty(out);
      setStatus('ok');
    }catch(e){
      $('genOut').textContent = pretty(e.body || {error:e.message, status:e.status});
      setStatus('error', false);
    }
  };

  $('statsBtn').onclick = async () => {
    $('statsOut').textContent='...';
    try{
      const out = await api('/admin/codes/stats');
      $('statsOut').textContent = pretty(out);
      setStatus('ok');
    }catch(e){
      $('statsOut').textContent = pretty(e.body || {error:e.message, status:e.status});
      setStatus('error', false);
    }
  };

  $('listBtn').onclick = async () => {
    $('statsOut').textContent='...';
    try{
      const limit = Number($('limit').value || 50);
      const out = await api('/admin/codes/list?limit=' + encodeURIComponent(limit));
      $('statsOut').textContent = pretty(out);
      setStatus('ok');
    }catch(e){
      $('statsOut').textContent = pretty(e.body || {error:e.message, status:e.status});
      setStatus('error', false);
    }
  };

  $('disableBtn').onclick = async () => {
    $('disableOut').textContent='...';
    try{
      const out = await api('/admin/codes/disable', {method:'POST', body: JSON.stringify({
        code: $('disableCode').value || null,
        codeHash: $('disableHash').value || null,
      })});
      $('disableOut').textContent = pretty(out);
      setStatus('ok');
    }catch(e){
      $('disableOut').textContent = pretty(e.body || {error:e.message, status:e.status});
      setStatus('error', false);
    }
  };

  $('revokeBtn').onclick = async () => {
    $('revokeOut').textContent='...';
    try{
      const out = await api('/admin/users/revoke', {method:'POST', body: JSON.stringify({
        userId: $('revokeUser').value || null,
      })});
      $('revokeOut').textContent = pretty(out);
      setStatus('ok');
    }catch(e){
      $('revokeOut').textContent = pretty(e.body || {error:e.message, status:e.status});
      setStatus('error', false);
    }
  };
</script>
</body></html>`);
});

// ---------- Start ----------
initDbIfPossible().finally(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log('[IAP] Verification server running on port', PORT);
    console.log('      Package:', PACKAGE_NAME || '(not set)');
    console.log('      Key:', process.env.GOOGLE_APPLICATION_CREDENTIALS || (SERVICE_ACCOUNT_JSON ? '(via SERVICE_ACCOUNT_JSON)' : '(not set)'));
    if (API_KEY) console.log('      API key required: yes');
    if (ALLOWED_ORIGIN) console.log('      CORS origin:', ALLOWED_ORIGIN);
    console.log('      ACK_ON_VERIFY:', ACK_ON_VERIFY);
    console.log('      ACK_ONLY_IF_ACTIVE:', ACK_ONLY_IF_ACTIVE);
    console.log('      ENTITLE_WHILE_NOT_EXPIRED:', ENTITLE_WHILE_NOT_EXPIRED);
    console.log('      ENTITLE_REQUIRE_ACK:', ENTITLE_REQUIRE_ACK);
    console.log('      ACK_REFRESH_RETRIES:', ACK_REFRESH_RETRIES);
    console.log('      ACK_REFRESH_DELAY_MS:', ACK_REFRESH_DELAY_MS);
    console.log('      CODES enabled:', !!CODE_PEPPER, 'storage:', db.enabled ? 'postgres' : 'memory');
    console.log('      ADMIN_KEY set:', !!ADMIN_KEY);
  });
});
