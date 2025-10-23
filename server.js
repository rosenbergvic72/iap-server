// iap-server/server.js
//
// Minimal Google Play Subscription verifier for Render/Railway/Fly etc.
// - Health:           GET  /
// - Verify purchase:  POST /iap/google/subscription/verify
//
// Env vars you may want to set on the host (Render -> Settings -> Environment):
//   PORT                         (Render provides automatically)
//   PACKAGE_NAME                 e.g. com.rosenbergvictor72.pealim2
//   SERVICE_ACCOUNT_JSON         (paste the raw JSON key content here)  OR
//   GOOGLE_APPLICATION_CREDENTIALS (path to service-account.json in container)
//   API_KEY                      (optional; if set, client must send x-api-key header)
//   ALLOWED_ORIGIN               (optional; CORS allow-origin; default "*")
//
// Client should POST JSON:
//   { userId, productId, packageName, purchaseToken }
//
// Notes:
// - Tries SubscriptionsV2 first (no productId needed), then falls back to v1 (needs productId).
// - Masks purchaseToken in logs.
// - Acknowledgement is done on-device via RN-IAP; server only verifies.
//
// Run locally:
//   set GOOGLE_APPLICATION_CREDENTIALS=.\service-account.json
//   set PACKAGE_NAME=com.rosenbergvictor72.pealim2
//   node server.js
//

const fs = require('fs');
const express = require('express');
const bodyParser = require('body-parser');
const { google } = require('googleapis');

// ---------- Config / Env ----------
const PORT = process.env.PORT || 3000;
const PACKAGE_NAME = process.env.PACKAGE_NAME || '';

const API_KEY = process.env.API_KEY || '';                 // if set, require x-api-key
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '';   // CORS allow-origin; "" -> "*"
const ENABLE_CORS = true;

// If GOOGLE_APPLICATION_CREDENTIALS is not set but SERVICE_ACCOUNT_JSON is,
// materialize a local file so GoogleAuth can read it.
if (!process.env.GOOGLE_APPLICATION_CREDENTIALS) {
  const raw = process.env.SERVICE_ACCOUNT_JSON;
  if (raw) {
    const path = './service-account.json';
    try {
      fs.writeFileSync(path, raw);
      process.env.GOOGLE_APPLICATION_CREDENTIALS = path;
      console.log('[IAP] Materialized service-account.json from env');
    } catch (e) {
      console.error('[IAP] Failed to write service-account.json:', e.message);
    }
  }
}

try {
  let raw = process.env.SERVICE_ACCOUNT_JSON || null;
  if (!raw && process.env.GOOGLE_APPLICATION_CREDENTIALS) {
    raw = fs.readFileSync(process.env.GOOGLE_APPLICATION_CREDENTIALS, 'utf8');
  }
  if (raw) {
    const sa = JSON.parse(raw);
    console.log('[IAP] Using service account:', sa.client_email, 'project_id:', sa.project_id);
  } else {
    console.warn('[IAP] Service account JSON not found (no SERVICE_ACCOUNT_JSON and no GOOGLE_APPLICATION_CREDENTIALS file)');
  }
} catch (e) {
  console.error('[IAP] Could not read/parse service-account JSON for log:', e.message);
}

// ---------- Helpers ----------
function maskToken(t, keep = 6) {
  if (!t || typeof t !== 'string') return '';
  const head = t.slice(0, keep);
  return `${head}…(${t.length})`;
}

function msToIso(ms) {
  const n = Number(ms);
  if (!Number.isFinite(n)) return null;
  try {
    return new Date(n).toISOString();
  } catch {
    return null;
  }
}

function pickMaxExpiryISO(expiries = []) {
  const ms = expiries
    .map((x) => (x ? Date.parse(x) : NaN))
    .filter((n) => Number.isFinite(n));
  if (!ms.length) return null;
  return new Date(Math.max(...ms)).toISOString();
}

// Normalize SubscriptionsV2 response
function normalizeV2(resp) {
  const d = resp?.data || {};
  const state = d.subscriptionState || ''; // e.g. SUBSCRIPTION_STATE_ACTIVE / CANCELED / IN_GRACE_PERIOD / ON_HOLD
  const activeStates = new Set([
    'SUBSCRIPTION_STATE_ACTIVE',
    'SUBSCRIPTION_STATE_IN_GRACE_PERIOD',
    'SUBSCRIPTION_STATE_ON_HOLD',
    'SUBSCRIPTION_STATE_PAUSED', // just in case
  ]);

  // expiryTime appears per lineItem (RFC3339). Pick max.
  const expiries = Array.isArray(d.lineItems)
    ? d.lineItems.map((li) => li?.expiryTime).filter(Boolean)
    : [];
  const expiresAtISO = pickMaxExpiryISO(expiries);

  // renewalState may exist (string). If missing, leave undefined.
  // Possible values (docs evolve): RENEWAL_STATE_REVOKED/CANCELED/RENEWED/PENDING etc.
  // We'll infer willRenew conservatively if renewalState hints "RENEWED" or similar.
  const renewalState = d.renewalState || '';
  const willRenew =
    renewalState &&
    /RENEW/i.test(String(renewalState)) &&
    !/CANCEL|REVOKE/i.test(String(renewalState))
      ? true
      : undefined;

  return {
    source: 'v2',
    active: activeStates.has(state),
    willRenew,
    expiresAtISO,
    subscriptionState: state,
    acknowledgementState: d.acknowledgementState || undefined,
    orderId: d.latestOrderId || undefined,
    regionCode: d.regionCode || undefined,
  };
}

// Normalize v1 response (purchases.subscriptions.get)
function normalizeV1(resp) {
  const d = resp?.data || {};
  const expiryMs = Number(d.expiryTimeMillis || 0);
  const expiresAtISO = msToIso(expiryMs);
  const nowActive = Number.isFinite(expiryMs) && expiryMs > Date.now();

  // willRenew = autoRenewing && not user-canceled (cancelReason=0 or null)
  // cancelReason: 0 = user canceled, 1 = system canceled, 2 = replaced by new sub, 3 = developer canceled
  let willRenew = undefined;
  if (typeof d.autoRenewing === 'boolean') {
    const canceled = d.cancelReason === 0 || d.cancelReason === 1 || d.cancelReason === 3;
    willRenew = d.autoRenewing && !canceled;
  }

  return {
    source: 'v1',
    active: !!nowActive,
    willRenew,
    expiresAtISO,
    paymentState: d.paymentState,
    cancelReason: d.cancelReason,
    orderId: d.orderId,
    acknowledgementState: d.acknowledgementState,
    priceCurrencyCode: d.priceCurrencyCode,
    priceAmountMicros: d.priceAmountMicros,
  };
}

let publisherClient = null;
async function getAndroidPublisher() {
  if (publisherClient) return publisherClient;
  const auth = new google.auth.GoogleAuth({
    scopes: ['https://www.googleapis.com/auth/androidpublisher'],
  });
  const authClient = await auth.getClient();
  publisherClient = google.androidpublisher({ version: 'v3', auth: authClient });
  return publisherClient;
}

// ---------- App ----------
const app = express();
app.use(bodyParser.json());

// CORS
if (ENABLE_CORS) {
  app.use((req, res, next) => {
    const origin = ALLOWED_ORIGIN || '*';
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'POST,GET,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization,x-api-key');
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    next();
  });
}

// Health
app.get('/', (req, res) => {
  res.json({
    ok: true,
    service: 'google-play-iap-verifier',
    package: PACKAGE_NAME || null,
    cors: ALLOWED_ORIGIN || '*',
    v: '1.0.0',
  });
});

// Verify endpoint
app.post('/iap/google/subscription/verify', async (req, res) => {
  try {
    // API key (optional)
    if (API_KEY) {
      const provided = req.header('x-api-key') || '';
      if (provided !== API_KEY) {
        return res.status(401).json({ ok: false, error: 'unauthorized' });
      }
    }

    const { userId, productId, packageName, purchaseToken } = req.body || {};
    const pkg = packageName || PACKAGE_NAME;

    if (!purchaseToken) {
      return res.status(400).json({ ok: false, error: 'purchaseToken is required' });
    }
    if (!pkg) {
      return res.status(400).json({ ok: false, error: 'packageName is required' });
    }

    const publisher = await getAndroidPublisher();

    let normalized = null;
    let used = 'v2';

    // Try V2 (doesn't require productId)
    try {
      const v2 = await publisher.purchases.subscriptionsv2.get({
        packageName: pkg,
        token: purchaseToken,
      });
      normalized = normalizeV2(v2);
    } catch (e) {
      used = 'v1';
    }

    // Fallback to V1 (requires productId)
    if (!normalized) {
      if (!productId) {
        return res.status(400).json({
          ok: false,
          error: 'productId is required for v1 fallback',
        });
      }
      const v1 = await publisher.purchases.subscriptions.get({
        packageName: pkg,
        subscriptionId: productId,
        token: purchaseToken,
      });
      normalized = normalizeV1(v1);
    }

    console.log('[IAP] verify ok:', {
      userId: userId || null,
      productId: productId || null,
      packageName: pkg,
      tokenMasked: maskToken(purchaseToken),
      source: normalized.source,
      pro: !!normalized.active,
      willRenew: normalized.willRenew,
      expiresAt: normalized.expiresAtISO || null,
    });

    res.json({
      ok: true,
      packageName: pkg,
      userId: userId || null,
      productId: productId || null,
      pro: !!normalized.active,
      ...normalized,
    });
  } catch (err) {
    const code = err?.response?.status || 500;
    console.error('[IAP] verify error:', {
      status: code,
      message: err?.message,
      google: err?.response?.data ? true : false,
    });
    res.status(code).json({
      ok: false,
      error: err?.response?.data || err?.message || 'Unknown error',
    });
  }
});

// ---------- Start ----------
app.listen(PORT, '0.0.0.0', () => {
  console.log('[IAP] Verification server running on port', PORT);
  console.log('      Package:', PACKAGE_NAME || '(not set)');
  console.log('      Key:', process.env.GOOGLE_APPLICATION_CREDENTIALS || '(via SERVICE_ACCOUNT_JSON or not set)');
  if (API_KEY) console.log('      API key required: yes');
  if (ALLOWED_ORIGIN) console.log('      CORS origin:', ALLOWED_ORIGIN);
});
