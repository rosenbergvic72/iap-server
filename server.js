// server.js
//
// Google Play subscription verifier + Partner/School access codes + Mini Admin (browser)
//
// Routes:
//   GET  /                               health
//   POST /iap/google/subscription/verify  verify Google Play subscription (v2->v1 fallback)
//   POST /redeem/code                     redeem partner/school code (one-time)
//   GET  /entitlements?userId=...         check partner-code entitlement
//
//   GET  /admin                           mini admin UI (HTML)
//   GET  /admin/codes/stats               stats (requires x-admin-key)
//   POST /admin/codes/generate            generate codes (requires x-admin-key)
//
// Env vars (IAP):
//   PORT
//   PACKAGE_NAME
//   SERVICE_ACCOUNT_JSON                 (raw JSON string)  OR GOOGLE_APPLICATION_CREDENTIALS (path)
//   API_KEY                              (optional; if set, client must send x-api-key)
//   ALLOWED_ORIGIN                       (optional; default "*")
//
//   ACK_ON_VERIFY=1                       (optional)
//   ACK_ONLY_IF_ACTIVE=1                  (optional; default 1)
//   ENTITLE_WHILE_NOT_EXPIRED=1           (optional; default 1)
//   ENTITLE_REQUIRE_ACK=0                 (optional; default 0)
//   ACK_REFRESH_RETRIES=2                 (optional)
//   ACK_REFRESH_DELAY_MS=250              (optional)
//
// Env vars (Codes):
//   CODE_PEPPER                           (required to enable codes; long random secret)
//   DATABASE_URL                          (optional; enables Postgres persistence)
//   PGSSLMODE=disable                      (optional; to disable ssl)
//   ADMIN_KEY                             (optional; enables /admin stats + /admin generate)
//   SEED_TEST_CODES=1                      (optional; seeds TEST-1DAY and TEST-2DAYS)
//
// Dependencies:
//   npm i express body-parser googleapis jsonwebtoken pg
//

const express = require('express');
const bodyParser = require('body-parser');
const { google } = require('googleapis');
const crypto = require('crypto');

const app = express();
app.use(bodyParser.json());

// -------------------- ENV / CONFIG --------------------
const PORT = process.env.PORT || 3000;

const PACKAGE_NAME = process.env.PACKAGE_NAME || '';
const API_KEY = process.env.API_KEY || '';
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';

const ACK_ON_VERIFY = process.env.ACK_ON_VERIFY === '1';
const ACK_ONLY_IF_ACTIVE = process.env.ACK_ONLY_IF_ACTIVE !== '0';
const ENTITLE_WHILE_NOT_EXPIRED = process.env.ENTITLE_WHILE_NOT_EXPIRED !== '0';
const ENTITLE_REQUIRE_ACK = process.env.ENTITLE_REQUIRE_ACK === '1';
const ACK_REFRESH_RETRIES = Number(process.env.ACK_REFRESH_RETRIES || 2);
const ACK_REFRESH_DELAY_MS = Number(process.env.ACK_REFRESH_DELAY_MS || 250);

const CODE_PEPPER = process.env.CODE_PEPPER || '';
const ADMIN_KEY = process.env.ADMIN_KEY || '';

// -------------------- CORS --------------------
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGIN || '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST,GET,OPTIONS');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'Content-Type,Authorization,x-api-key,x-admin-key'
  );
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// -------------------- Helpers --------------------
function maskToken(t, keep = 6) {
  if (!t || typeof t !== 'string') return '';
  const head = t.slice(0, keep);
  return `${head}…(${t.length})`;
}

function requireApiKeyIfSet(req, res) {
  if (!API_KEY) return true;
  const provided = req.header('x-api-key') || '';
  if (provided !== API_KEY) {
    res.status(401).json({ ok: false, error: 'unauthorized' });
    return false;
  }
  return true;
}

function requireAdminKey(req, res) {
  if (!ADMIN_KEY) {
    res.status(403).json({ ok: false, error: 'ADMIN_KEY_not_set' });
    return false;
  }
  const provided = req.header('x-admin-key') || '';
  if (provided !== ADMIN_KEY) {
    res.status(401).json({ ok: false, error: 'unauthorized' });
    return false;
  }
  return true;
}

function isoOrNull(x) {
  try {
    if (!x) return null;
    const d = new Date(x);
    if (Number.isNaN(d.getTime())) return null;
    return d.toISOString();
  } catch {
    return null;
  }
}

function isNotExpired(expiresAtISO) {
  if (!expiresAtISO) return false;
  const t = Date.parse(expiresAtISO);
  if (Number.isNaN(t)) return false;
  return t > Date.now();
}

// -------------------- Google Auth --------------------
function loadServiceAccount() {
  if (!process.env.SERVICE_ACCOUNT_JSON) return null;
  try {
    return JSON.parse(process.env.SERVICE_ACCOUNT_JSON);
  } catch (e) {
    console.error('[IAP] SERVICE_ACCOUNT_JSON parse error:', e.message);
    return null;
  }
}

function getAuthClient() {
  const sa = loadServiceAccount();
  if (sa) {
    return new google.auth.JWT(sa.client_email, null, sa.private_key, [
      'https://www.googleapis.com/auth/androidpublisher',
    ]);
  }
  // fallback: GOOGLE_APPLICATION_CREDENTIALS
  return new google.auth.GoogleAuth({
    scopes: ['https://www.googleapis.com/auth/androidpublisher'],
  });
}

const authClient = getAuthClient();
const publisher = google.androidpublisher({ version: 'v3', auth: authClient });

// -------------------- Normalize Google responses --------------------
function normalizeV2(v2) {
  const data = v2?.data || v2 || {};
  const line = data?.lineItems?.[0] || null;

  const expiresAtISO = isoOrNull(line?.expiryTime);

  const ackState = line?.acknowledgementState || null;
  const isAcked =
    ackState === 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED' ||
    ackState === 1 ||
    ackState === '1';

  const willRenew = !!line?.autoRenewing;
  const rawState = line?.subscriptionState || data?.subscriptionState || null;

  return {
    api: 'v2',
    raw: data,
    subscriptionState: rawState,
    acknowledgementState: ackState,
    isAcked,
    willRenew,
    expiresAtISO,
  };
}

function normalizeV1(v1) {
  const data = v1?.data || v1 || {};
  const expMs = data?.expiryTimeMillis ? Number(data.expiryTimeMillis) : null;
  const expiresAtISO = expMs ? new Date(expMs).toISOString() : null;

  const ackState = data?.acknowledgementState;
  const isAcked = Number(ackState) === 1;

  const willRenew = !!data?.autoRenewing;

  return {
    api: 'v1',
    raw: data,
    acknowledgementState: ackState,
    isAcked,
    willRenew,
    expiresAtISO,
  };
}

async function ackIfNeeded({ pkg, productId, purchaseToken, normalized }) {
  if (!ACK_ON_VERIFY) return { tried: false, ok: false, reason: 'ack-disabled' };

  const notExpired = isNotExpired(normalized?.expiresAtISO);
  if (ACK_ONLY_IF_ACTIVE && !notExpired) return { tried: false, ok: false, reason: 'not-active' };

  if (normalized?.isAcked) return { tried: false, ok: true, reason: 'already-acked' };

  const withRetry = async (fn) => {
    let lastErr = null;
    for (let i = 0; i <= ACK_REFRESH_RETRIES; i++) {
      try {
        await fn();
        return { ok: true, err: null };
      } catch (e) {
        lastErr = e;
        if (i < ACK_REFRESH_RETRIES) {
          await new Promise((r) => setTimeout(r, ACK_REFRESH_DELAY_MS));
        }
      }
    }
    return { ok: false, err: lastErr };
  };

  const tryAckV2 = async () => {
    await publisher.purchases.subscriptionsv2.acknowledge({
      packageName: pkg,
      token: purchaseToken,
      requestBody: {},
    });
  };

  const tryAckV1 = async () => {
    if (!productId) throw new Error('productId-required-for-v1-ack');
    await publisher.purchases.subscriptions.acknowledge({
      packageName: pkg,
      subscriptionId: productId,
      token: purchaseToken,
      requestBody: {},
    });
  };

  try {
    if (normalized?.api === 'v2') {
      const r = await withRetry(tryAckV2);
      if (!r.ok) throw r.err;
    } else {
      const r = await withRetry(tryAckV1);
      if (!r.ok) throw r.err;
    }

    return { tried: true, ok: true, reason: 'acked' };
  } catch (e) {
    const msg = e?.message || String(e);
    if (msg.toLowerCase().includes('already') || msg.toLowerCase().includes('acknowledged')) {
      return { tried: true, ok: true, reason: 'already-acked' };
    }
    if (msg.includes('not owned') || msg.includes('Not owned')) {
      return { tried: true, ok: false, reason: 'not-owned' };
    }
    return { tried: true, ok: false, reason: 'ack-failed', error: msg };
  }
}

// -------------------- Codes store (Postgres or Memory) --------------------
let codesStore = null;

function normalizeAccessCode(raw) {
  return String(raw || '')
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9_-]/g, '');
}

function hashAccessCode(code) {
  if (!CODE_PEPPER) return null;
  return crypto.createHmac('sha256', CODE_PEPPER).update(code).digest('hex');
}

function isValidDurationDays(n) {
  return [1, 2, 90, 180, 365].includes(Number(n));
}

function calcAccessUntilISO(days) {
  const ms = Date.now() + Number(days) * 24 * 60 * 60 * 1000;
  return new Date(ms).toISOString();
}

async function initCodesStore() {
  const hasDb = !!process.env.DATABASE_URL;

  if (hasDb) {
    const { Pool } = require('pg');
    const pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.PGSSLMODE === 'disable' ? false : { rejectUnauthorized: false },
    });

    await pool.query(`CREATE EXTENSION IF NOT EXISTS pgcrypto;`);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS access_codes (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        partner_id TEXT,
        duration_days INT NOT NULL CHECK (duration_days IN (1,2,90,180,365)),
        code_hash TEXT NOT NULL UNIQUE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        disabled_at TIMESTAMPTZ,
        note TEXT
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS code_redemptions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        code_id UUID REFERENCES access_codes(id) ON DELETE CASCADE,
        user_id TEXT NOT NULL,
        redeemed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        access_until TIMESTAMPTZ NOT NULL,
        UNIQUE(code_id)
      );
    `);

    await pool.query(`CREATE INDEX IF NOT EXISTS idx_redemptions_user ON code_redemptions(user_id);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_redemptions_until ON code_redemptions(access_until);`);

    codesStore = {
      kind: 'postgres',
      _pool: pool,

      async redeem({ codeHash, userId }) {
        const c = await pool.query(
          `SELECT id, duration_days, disabled_at FROM access_codes WHERE code_hash = $1`,
          [codeHash]
        );
        if (c.rowCount === 0) return { ok: false, error: 'invalid_code' };
        const codeRow = c.rows[0];
        if (codeRow.disabled_at) return { ok: false, error: 'code_disabled' };

        const used = await pool.query(`SELECT user_id FROM code_redemptions WHERE code_id = $1`, [codeRow.id]);
        if (used.rowCount > 0) return { ok: false, error: 'code_already_used' };

        const accessUntil = calcAccessUntilISO(codeRow.duration_days);
        await pool.query(
          `INSERT INTO code_redemptions (code_id, user_id, access_until) VALUES ($1,$2,$3)`,
          [codeRow.id, userId, accessUntil]
        );
        return { ok: true, durationDays: codeRow.duration_days, accessUntil };
      },

      async getEntitlement({ userId }) {
        const r = await pool.query(
          `SELECT access_until FROM code_redemptions WHERE user_id = $1 ORDER BY access_until DESC LIMIT 1`,
          [userId]
        );
        if (r.rowCount === 0) return { pro: false, accessUntil: null };
        const until = r.rows[0].access_until ? new Date(r.rows[0].access_until).toISOString() : null;
        const pro = until ? Date.parse(until) > Date.now() : false;
        return { pro, accessUntil: until };
      },

      async generateCodes({ partnerId, durationDays, count, note }) {
        const codes = [];
        for (let i = 0; i < count; i++) {
          // readable: XXXX-XXXX-XXXX
          const raw = crypto
            .randomBytes(9)
            .toString('base64url')
            .toUpperCase()
            .replace(/[^A-Z0-9]/g, 'A')
            .slice(0, 12);

          const code = `${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}`;
          const codeHash = hashAccessCode(code);
          if (!codeHash) throw new Error('CODE_PEPPER is required');

          await pool.query(
            `INSERT INTO access_codes (partner_id, duration_days, code_hash, note) VALUES ($1,$2,$3,$4)`,
            [partnerId || null, durationDays, codeHash, note || null]
          );
          codes.push(code);
        }
        return codes;
      },

      async stats() {
        const q = `
          SELECT
            COALESCE(ac.partner_id,'') AS partner_id,
            ac.duration_days,
            COUNT(*)::int AS total,
            COUNT(cr.code_id)::int AS redeemed,
            (COUNT(*) - COUNT(cr.code_id))::int AS available
          FROM access_codes ac
          LEFT JOIN code_redemptions cr ON cr.code_id = ac.id
          WHERE ac.disabled_at IS NULL
          GROUP BY COALESCE(ac.partner_id,''), ac.duration_days
          ORDER BY partner_id, ac.duration_days;
        `;
        const r = await pool.query(q);
        return r.rows;
      },
    };

    console.log('[CODES] Store: Postgres');
    return;
  }

  // memory fallback (dev)
  const memoryCodes = new Map(); // codeHash -> { durationDays, disabled }
  const memoryRedeems = new Map(); // codeHash -> { userId, accessUntil }

  codesStore = {
    kind: 'memory',

    async redeem({ codeHash, userId }) {
      const row = memoryCodes.get(codeHash);
      if (!row) return { ok: false, error: 'invalid_code' };
      if (row.disabled) return { ok: false, error: 'code_disabled' };
      if (memoryRedeems.has(codeHash)) return { ok: false, error: 'code_already_used' };
      const accessUntil = calcAccessUntilISO(row.durationDays);
      memoryRedeems.set(codeHash, { userId, accessUntil });
      return { ok: true, durationDays: row.durationDays, accessUntil };
    },

    async getEntitlement({ userId }) {
      let best = null;
      for (const { userId: u, accessUntil } of memoryRedeems.values()) {
        if (u !== userId) continue;
        if (!best || Date.parse(accessUntil) > Date.parse(best)) best = accessUntil;
      }
      const pro = best ? Date.parse(best) > Date.now() : false;
      return { pro, accessUntil: best };
    },

    async generateCodes({ partnerId, durationDays, count, note }) {
      const codes = [];
      for (let i = 0; i < count; i++) {
        const raw = crypto
          .randomBytes(9)
          .toString('base64url')
          .toUpperCase()
          .replace(/[^A-Z0-9]/g, 'A')
          .slice(0, 12);
        const code = `${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}`;
        const codeHash = hashAccessCode(code);
        if (!codeHash) throw new Error('CODE_PEPPER is required');
        memoryCodes.set(codeHash, {
          durationDays: Number(durationDays),
          disabled: false,
          partnerId: partnerId || null,
          note: note || null,
        });
        codes.push(code);
      }
      return codes;
    },

    async stats() {
      // minimal stats for memory mode (not used in prod)
      const counts = new Map(); // key = partner|days -> {total, redeemed}
      for (const [h, row] of memoryCodes.entries()) {
        const key = `${row.partnerId || ''}||${row.durationDays}`;
        if (!counts.has(key)) counts.set(key, { partner_id: row.partnerId || '', duration_days: row.durationDays, total: 0, redeemed: 0 });
        counts.get(key).total += 1;
        if (memoryRedeems.has(h)) counts.get(key).redeemed += 1;
      }
      return Array.from(counts.values()).map(r => ({ ...r, available: r.total - r.redeemed }))
        .sort((a,b) => (a.partner_id.localeCompare(b.partner_id) || a.duration_days - b.duration_days));
    },

    _seedPlainCodes(list) {
      for (const item of list) {
        const code = normalizeAccessCode(item.code);
        const codeHash = hashAccessCode(code);
        if (codeHash) memoryCodes.set(codeHash, { durationDays: Number(item.durationDays), disabled: false, partnerId: '__TEST__' });
      }
    },
  };

  console.log('[CODES] Store: In-Memory (set DATABASE_URL for persistence)');
}

async function seedTestCodesIfNeeded() {
  if (process.env.SEED_TEST_CODES !== '1') return;
  if (!CODE_PEPPER) {
    console.warn('[CODES] SEED_TEST_CODES=1 but CODE_PEPPER is missing; skip seeding');
    return;
  }
  if (!codesStore) return;

  const test = [
    { code: 'TEST-1DAY', durationDays: 1 },
    { code: 'TEST-2DAYS', durationDays: 2 },
  ];

  if (codesStore.kind === 'memory') {
    codesStore._seedPlainCodes(test);
    console.log('[CODES] Seeded TEST codes (memory)');
    return;
  }

  // postgres: upsert by hash
  for (const t of test) {
    const h = hashAccessCode(normalizeAccessCode(t.code));
    if (!h) continue;
    await codesStore._pool.query(
      `INSERT INTO access_codes (partner_id, duration_days, code_hash, note)
       VALUES ($1,$2,$3,$4)
       ON CONFLICT (code_hash) DO NOTHING`,
      ['__TEST__', Number(t.durationDays), h, 'seed test code']
    );
  }
  console.log('[CODES] Seeded TEST codes (postgres)');
}

// -------------------- Health --------------------
app.get('/', (req, res) => {
  res.json({
    ok: true,
    service: 'iap+codes',
    package: PACKAGE_NAME || null,
    cors: ALLOWED_ORIGIN || '*',
    ackOnVerify: ACK_ON_VERIFY,
    ackOnlyIfActive: ACK_ONLY_IF_ACTIVE,
    entitleWhileNotExpired: ENTITLE_WHILE_NOT_EXPIRED,
    entitleRequireAck: ENTITLE_REQUIRE_ACK,
    codesEnabled: !!CODE_PEPPER,
    codesStore: codesStore?.kind || null,
    adminEnabled: !!ADMIN_KEY,
  });
});

// -------------------- Mini Admin UI (browser) --------------------
app.get('/admin', (req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(`<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Verbify Mini Admin</title>
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:24px;background:#0b1020;color:#e6e8ef}
    .row{display:flex;gap:16px;flex-wrap:wrap}
    .card{background:#121a33;border:1px solid #22305a;border-radius:12px;padding:16px;max-width:980px}
    input,select,button,textarea{font:inherit;border-radius:10px;border:1px solid #2a3a6a;background:#0e1630;color:#e6e8ef;padding:10px}
    input,select,textarea{width:100%}
    label{display:block;margin:10px 0 6px;color:#aab2d5}
    button{cursor:pointer;background:#2a5bff;border-color:#2a5bff}
    button.secondary{background:#0e1630;border-color:#2a3a6a}
    .mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace}
    .ok{color:#6ee7b7}
    .err{color:#fca5a5}
    table{border-collapse:collapse;width:100%;margin-top:10px}
    th,td{border-bottom:1px solid #22305a;padding:8px;text-align:left;font-size:14px}
    .small{font-size:12px;color:#aab2d5}
    .pill{display:inline-block;padding:3px 8px;border-radius:999px;background:#0e1630;border:1px solid #22305a}
  </style>
</head>
<body>
  <h1>Verbify Mini Admin</h1>
  <p class="small">Коды показываются <b>только при генерации</b> (в базе хранится только hash — это безопасно).</p>

  <div class="row">
    <div class="card" style="flex:1;min-width:300px">
      <h2>Auth</h2>
      <label>ADMIN_KEY</label>
      <input id="adminKey" type="password" placeholder="Вставь ADMIN_KEY" />
      <div style="margin-top:10px;display:flex;gap:10px;flex-wrap:wrap">
        <button class="secondary" onclick="saveKey()">Сохранить в браузере</button>
        <button class="secondary" onclick="clearKey()">Очистить</button>
        <span id="authState" class="pill">не задан</span>
      </div>
    </div>

    <div class="card" style="flex:2;min-width:320px">
      <h2>Generate codes</h2>

      <div class="row">
        <div style="flex:1;min-width:220px">
          <label>partnerId</label>
          <input id="partnerId" placeholder="например: schoolA / teacher_levin" />
        </div>
        <div style="flex:1;min-width:220px">
          <label>durationDays</label>
          <select id="durationDays">
            <option value="1">1 (тест)</option>
            <option value="2">2 (тест)</option>
            <option value="90">90 (3 месяца)</option>
            <option value="180">180 (6 месяцев)</option>
            <option value="365">365 (12 месяцев)</option>
          </select>
        </div>
        <div style="flex:1;min-width:160px">
          <label>count</label>
          <input id="count" type="number" min="1" max="5000" value="10" />
        </div>
      </div>

      <label>note</label>
      <input id="note" placeholder="например: Jan 2026 batch A" />

      <div style="margin-top:12px;display:flex;gap:10px;flex-wrap:wrap">
        <button onclick="generate()">Сгенерировать</button>
        <button class="secondary" onclick="downloadCSV()" id="dlBtn" disabled>Скачать CSV</button>
        <span id="genStatus" class="pill">—</span>
      </div>

      <div style="margin-top:12px">
        <label>Результат (коды)</label>
        <textarea id="codesBox" rows="8" class="mono" placeholder="Здесь появятся коды..." readonly></textarea>
      </div>
    </div>
  </div>

  <div class="card" style="margin-top:16px">
    <h2>Stats</h2>
    <div style="display:flex;gap:10px;flex-wrap:wrap">
      <button class="secondary" onclick="loadStats()">Обновить статистику</button>
      <span id="statsStatus" class="pill">—</span>
    </div>
    <div id="statsTable"></div>
  </div>

<script>
  let lastGenerated = null;

  function getKey(){ return sessionStorage.getItem('ADMIN_KEY') || ''; }
  function setKey(k){ sessionStorage.setItem('ADMIN_KEY', k); }

  function setAuth(ok){
    const el = document.getElementById('authState');
    el.textContent = ok ? 'ключ задан' : 'не задан';
    el.className = 'pill ' + (ok ? 'ok' : '');
  }

  function saveKey(){
    const k = document.getElementById('adminKey').value.trim();
    if (!k) return setAuth(false);
    setKey(k);
    setAuth(true);
  }

  function clearKey(){
    sessionStorage.removeItem('ADMIN_KEY');
    document.getElementById('adminKey').value = '';
    setAuth(false);
  }

  function setPill(id, text, ok){
    const el = document.getElementById(id);
    el.textContent = text;
    el.className = 'pill ' + (ok ? 'ok' : 'err');
  }

  setAuth(!!getKey());

  async function generate(){
    const adminKey = getKey();
    if (!adminKey) return setPill('genStatus', 'ADMIN_KEY не задан', false);

    const partnerId = document.getElementById('partnerId').value.trim();
    const durationDays = Number(document.getElementById('durationDays').value);
    const count = Number(document.getElementById('count').value);
    const note = document.getElementById('note').value.trim();

    document.getElementById('codesBox').value = '';
    document.getElementById('dlBtn').disabled = true;
    lastGenerated = null;

    setPill('genStatus', 'генерация…', true);

    const r = await fetch('/admin/codes/generate', {
      method: 'POST',
      headers: { 'Content-Type':'application/json', 'x-admin-key': adminKey },
      body: JSON.stringify({ partnerId, durationDays, count, note })
    });

    const data = await r.json().catch(()=>null);
    if (!r.ok){
      setPill('genStatus', 'ошибка: ' + (data?.error || r.status), false);
      return;
    }

    const codes = data?.codes || [];
    lastGenerated = { partnerId, durationDays, note, codes };
    document.getElementById('codesBox').value = codes.join('\\n');
    document.getElementById('dlBtn').disabled = codes.length === 0;
    setPill('genStatus', 'готово: ' + codes.length, true);

    loadStats();
  }

  function downloadCSV(){
    if (!lastGenerated) return;
    const { partnerId, durationDays, note, codes } = lastGenerated;

    const rows = [['code','partnerId','durationDays','note'], ...codes.map(c => [c, partnerId||'', String(durationDays), note||''])];

    const csv = rows.map(r => r.map(v => {
      const s = String(v ?? '');
      return /[",\\n]/.test(s) ? '"' + s.replace(/"/g,'""') + '"' : s;
    }).join(',')).join('\\n');

    const blob = new Blob([csv], { type:'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'codes_' + (partnerId || 'partner') + '_' + durationDays + 'd.csv';
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  async function loadStats(){
    const adminKey = getKey();
    if (!adminKey) return setPill('statsStatus', 'ADMIN_KEY не задан', false);

    setPill('statsStatus', 'загрузка…', true);

    const r = await fetch('/admin/codes/stats', { headers: { 'x-admin-key': adminKey } });
    const data = await r.json().catch(()=>null);

    if (!r.ok){
      setPill('statsStatus', 'ошибка: ' + (data?.error || r.status), false);
      return;
    }

    setPill('statsStatus', 'ok', true);
    renderStats(data);
  }

  function escapeHtml(s){
    return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  function renderStats(data){
    const rows = data?.rows || [];
    if (!rows.length){
      document.getElementById('statsTable').innerHTML = '<p class="small">Нет данных.</p>';
      return;
    }

    const html = \`
      <table>
        <thead>
          <tr>
            <th>partnerId</th>
            <th>durationDays</th>
            <th>total</th>
            <th>redeemed</th>
            <th>available</th>
          </tr>
        </thead>
        <tbody>
          \${rows.map(r => \`
            <tr>
              <td>\${escapeHtml(r.partner_id ?? '')}</td>
              <td>\${r.duration_days}</td>
              <td>\${r.total}</td>
              <td>\${r.redeemed}</td>
              <td>\${r.available}</td>
            </tr>
          \`).join('')}
        </tbody>
      </table>\`;

    document.getElementById('statsTable').innerHTML = html;
  }
</script>
</body>
</html>`);
});

// -------------------- Admin Stats --------------------
app.get('/admin/codes/stats', async (req, res) => {
  try {
    if (!requireAdminKey(req, res)) return;
    if (!CODE_PEPPER || !codesStore) return res.json({ ok: true, rows: [] });
    const rows = await codesStore.stats();
    return res.json({ ok: true, rows });
  } catch (e) {
    console.error('[ADMIN] stats error:', e);
    return res.status(500).json({ ok: false, error: 'internal_error' });
  }
});

// -------------------- Admin Generate Codes --------------------
app.post('/admin/codes/generate', async (req, res) => {
  try {
    if (!requireAdminKey(req, res)) return;

    const { partnerId, durationDays, count, note } = req.body || {};
    const days = Number(durationDays);
    const n = Math.max(1, Math.min(5000, Number(count || 0)));

    if (!isValidDurationDays(days)) {
      return res.status(400).json({ ok: false, error: 'invalid_duration_days' });
    }
    if (!CODE_PEPPER) return res.status(500).json({ ok: false, error: 'CODE_PEPPER_not_set' });
    if (!codesStore) return res.status(500).json({ ok: false, error: 'codes_store_not_ready' });

    const codes = await codesStore.generateCodes({
      partnerId: String(partnerId || ''),
      durationDays: days,
      count: n,
      note: note || null,
    });

    return res.json({ ok: true, partnerId: partnerId || null, durationDays: days, count: codes.length, codes });
  } catch (e) {
    console.error('[ADMIN] generate error:', e);
    return res.status(500).json({ ok: false, error: 'internal_error' });
  }
});

// -------------------- Redeem Code --------------------
app.post('/redeem/code', async (req, res) => {
  try {
    if (!requireApiKeyIfSet(req, res)) return;

    const { code, userId } = req.body || {};
    const norm = normalizeAccessCode(code);

    if (!userId) return res.status(400).json({ ok: false, error: 'userId_required' });
    if (!norm) return res.status(400).json({ ok: false, error: 'code_required' });
    if (!CODE_PEPPER) return res.status(500).json({ ok: false, error: 'CODE_PEPPER_not_set' });
    if (!codesStore) return res.status(500).json({ ok: false, error: 'codes_store_not_ready' });

    const codeHash = hashAccessCode(norm);
    const out = await codesStore.redeem({ codeHash, userId: String(userId) });

    if (!out.ok) {
      const status =
        out.error === 'invalid_code' ? 404 :
        out.error === 'code_disabled' ? 410 :
        out.error === 'code_already_used' ? 409 : 400;
      return res.status(status).json({ ok: false, error: out.error });
    }

    return res.json({
      ok: true,
      pro: true,
      entitled: true,
      source: 'partner_code',
      durationDays: out.durationDays,
      accessUntil: out.accessUntil,
    });
  } catch (e) {
    console.error('[CODES] redeem error:', e);
    return res.status(500).json({ ok: false, error: 'internal_error' });
  }
});

// -------------------- Entitlements (Codes only) --------------------
app.get('/entitlements', async (req, res) => {
  try {
    if (!requireApiKeyIfSet(req, res)) return;

    const userId = String(req.query?.userId || '').trim();
    if (!userId) return res.status(400).json({ ok: false, error: 'userId_required' });

    if (!CODE_PEPPER || !codesStore) {
      return res.json({ ok: true, pro: false, entitled: false, source: null, accessUntil: null });
    }

    const ent = await codesStore.getEntitlement({ userId });
    return res.json({
      ok: true,
      pro: !!ent.pro,
      entitled: !!ent.pro,
      source: ent.pro ? 'partner_code' : null,
      accessUntil: ent.accessUntil || null,
    });
  } catch (e) {
    console.error('[CODES] entitlements error:', e);
    return res.status(500).json({ ok: false, error: 'internal_error' });
  }
});

// -------------------- IAP Verify --------------------
app.post('/iap/google/subscription/verify', async (req, res) => {
  try {
    if (!requireApiKeyIfSet(req, res)) return;

    const { userId, productId, packageName, purchaseToken } = req.body || {};

    // --- Debug input (то самое изменение из "server") ---
    console.log('[IAP][VERIFY][INPUT]', {
      userId: userId || null,
      productId: productId || null,
      packageName_from_client: packageName || null,
      packageName_env: PACKAGE_NAME || null,
      pkg_effective: (packageName || PACKAGE_NAME) || null,
      purchaseToken_masked: purchaseToken ? maskToken(purchaseToken) : null,
      tokenLength: purchaseToken?.length ?? 0,
    });
    // ----------------------------------------------------

    if (!purchaseToken) {
      return res.status(400).json({ ok: false, error: 'purchaseToken_required' });
    }

    const pkg = packageName || PACKAGE_NAME;
    if (!pkg) {
      return res.status(400).json({ ok: false, error: 'packageName_required' });
    }

    let normalized = null;
    let used = 'v2';

    // Try V2 first
    try {
      const v2 = await publisher.purchases.subscriptionsv2.get({
        packageName: pkg,
        token: purchaseToken,
      });
      normalized = normalizeV2(v2);
    } catch (e) {
      used = 'v1';
    }

    // Fallback to V1 (needs productId)
    if (!normalized) {
      if (!productId) {
        return res.status(400).json({ ok: false, error: 'productId_required_for_v1' });
      }
      const v1 = await publisher.purchases.subscriptions.get({
        packageName: pkg,
        subscriptionId: productId,
        token: purchaseToken,
      });
      normalized = normalizeV1(v1);
    }

    const notExpired = isNotExpired(normalized.expiresAtISO);
    const isAcked = !!normalized.isAcked;

    // Entitlement policy
    let entitled = false;
    if (ENTITLE_WHILE_NOT_EXPIRED) {
      entitled = notExpired;
    } else {
      entitled = notExpired && !!normalized.willRenew;
    }

    if (ENTITLE_REQUIRE_ACK) {
      entitled = entitled && isAcked;
    }

    // ACK attempt (optional)
    const ack = await ackIfNeeded({
      pkg,
      productId,
      purchaseToken,
      normalized,
    });

    // OR with partner-code entitlement (if userId passed)
    let codeEnt = { pro: false, accessUntil: null };
    try {
      if (userId && CODE_PEPPER && codesStore) {
        codeEnt = await codesStore.getEntitlement({ userId: String(userId) });
      }
    } catch (e) {
      console.warn('[CODES] entitlement check failed (ignored):', e?.message || e);
    }

    const finalEntitled = !!entitled || !!codeEnt.pro;

    console.log('[IAP] verify', {
      userId: userId || null,
      packageName: pkg,
      productId: productId || null,
      used,
      api: normalized.api,
      subscriptionState: normalized.subscriptionState || null,
      acknowledgementState: normalized.acknowledgementState || null,
      willRenew: normalized.willRenew,
      expiresAt: normalized.expiresAtISO || null,
      notExpired,
      isAcked,
      entitled,
      pro: entitled,
      policy: {
        entitleWhileNotExpired: ENTITLE_WHILE_NOT_EXPIRED,
        entitleRequireAck: ENTITLE_REQUIRE_ACK,
      },
      ackOnVerify: ACK_ON_VERIFY,
      ackOnlyIfActive: ACK_ONLY_IF_ACTIVE,
      ackTried: ack.tried,
      ackOk: ack.ok,
      ackReason: ack.reason || null,
    });

    res.json({
      ok: true,
      packageName: pkg,
      userId: userId || null,
      productId: productId || null,
      source: entitled ? 'iap' : (codeEnt.pro ? 'partner_code' : null),
      codeAccessUntil: codeEnt.accessUntil || null,
      pro: finalEntitled,
      entitled: finalEntitled,
      notExpired,
      isAcked,
      ack: { tried: ack.tried, ok: ack.ok, reason: ack.reason || null },
      ...normalized,
      usedVersion: used,
    });
  } catch (err) {
    const status = err?.response?.status || 500;
    const data = err?.response?.data;

    // --- Expanded google error (то самое изменение из "server") ---
    console.error('[IAP][VERIFY][GOOGLE_ERROR]', {
      status,
      message: data?.error?.message || err?.message || null,
      errors: data?.error?.errors || null,
    });
    if (Array.isArray(data?.error?.errors) && data.error.errors.length) {
      console.error('[IAP][VERIFY][GOOGLE_ERROR][0]', JSON.stringify(data.error.errors[0], null, 2));
    }
    // --------------------------------------------------------------

    console.error('[IAP] verify error:', {
      status,
      message: err?.message,
      google: !!data,
      data: data || null,
    });

    res.status(status).json({
      ok: false,
      error: data || err?.message || 'Unknown error',
    });
  }
});

// -------------------- Startup --------------------
(async () => {
  try {
    await initCodesStore();
    await seedTestCodesIfNeeded();
  } catch (e) {
    console.error('[CODES] init failed:', e?.message || e);
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log('[IAP] Server running on port', PORT);
    console.log('      PACKAGE_NAME:', PACKAGE_NAME || '(not set)');
    console.log('      API_KEY required:', API_KEY ? 'yes' : 'no');
    console.log('      ALLOWED_ORIGIN:', ALLOWED_ORIGIN || '*');
    console.log('      ACK_ON_VERIFY:', ACK_ON_VERIFY);
    console.log('      ACK_ONLY_IF_ACTIVE:', ACK_ONLY_IF_ACTIVE);
    console.log('      ENTITLE_WHILE_NOT_EXPIRED:', ENTITLE_WHILE_NOT_EXPIRED);
    console.log('      ENTITLE_REQUIRE_ACK:', ENTITLE_REQUIRE_ACK);
    console.log('      ACK_REFRESH_RETRIES:', ACK_REFRESH_RETRIES);
    console.log('      ACK_REFRESH_DELAY_MS:', ACK_REFRESH_DELAY_MS);

    console.log('      Codes enabled:', CODE_PEPPER ? 'yes' : 'no');
    if (CODE_PEPPER) console.log('      Codes store:', codesStore?.kind || 'unknown');
    console.log('      Admin enabled:', ADMIN_KEY ? 'yes' : 'no');
    if (process.env.DATABASE_URL) console.log('      DATABASE_URL: set');
    if (process.env.SEED_TEST_CODES === '1') console.log('      SEED_TEST_CODES=1');
  });
})();
