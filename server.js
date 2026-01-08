// iap-server/server.js
//
// Minimal Google Play Subscription verifier for Render/Railway/Fly etc.
// - Health:           GET  /
// - Verify purchase:  POST /iap/google/subscription/verify
//
// Env vars you may want to set on the host (Render -> Settings -> Environment):
//   PORT
//   PACKAGE_NAME                      e.g. com.rosenbergvictor72.pealim2
//   SERVICE_ACCOUNT_JSON              (paste raw JSON key)  OR
//   GOOGLE_APPLICATION_CREDENTIALS    (path to service-account.json)
//   API_KEY                           (optional; if set, client must send x-api-key)
//   ALLOWED_ORIGIN                    (optional; CORS allow-origin; default "*")
//   ACK_ON_VERIFY                     (optional; "1" to auto-ack active subs on verify)
//   ACK_ONLY_IF_ACTIVE                (optional; default "1"; if "0", ack when not active too)
//   ENTITLE_WHILE_NOT_EXPIRED         (optional; default "1"; if "1", pro=true while not expired)
//   ENTITLE_REQUIRE_ACK               (optional; default "1"; if "1", pro requires acknowledged)
//
// Client should POST JSON:
//   { userId, productId, packageName, purchaseToken }
//
// Notes:
// - Tries SubscriptionsV2 first (no productId needed), then falls back to v1 (needs productId).
// - Masks purchaseToken in logs.
// - Can optionally acknowledge on server (recommended) if ACK_ON_VERIFY=1.
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

const ACK_ON_VERIFY = String(process.env.ACK_ON_VERIFY || '0') === '1';
const ACK_ONLY_IF_ACTIVE = String(process.env.ACK_ONLY_IF_ACTIVE || '1') === '1';

// Entitlement flags
const ENTITLE_WHILE_NOT_EXPIRED = String(process.env.ENTITLE_WHILE_NOT_EXPIRED || '1') === '1';
const ENTITLE_REQUIRE_ACK       = String(process.env.ENTITLE_REQUIRE_ACK || '1') === '1';

// Post-ACK refresh behavior
const ACK_REFRESH_RETRIES   = Number(process.env.ACK_REFRESH_RETRIES || 2);
const ACK_REFRESH_DELAY_MS  = Number(process.env.ACK_REFRESH_DELAY_MS || 1200);

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

const ACTIVE_STATES_V2 = new Set([
  'SUBSCRIPTION_STATE_ACTIVE',
  'SUBSCRIPTION_STATE_IN_GRACE_PERIOD',
  'SUBSCRIPTION_STATE_ON_HOLD',
  'SUBSCRIPTION_STATE_PAUSED',
]);

function isAckedValue(val) {
  const s = String(val ?? '');
  return /ACKNOWLEDGED/i.test(s) || s === '1';
}

// Normalize SubscriptionsV2 response
function normalizeV2(resp) {
  const d = resp?.data || {};
  const state = d.subscriptionState || '';
  const expiries = Array.isArray(d.lineItems)
    ? d.lineItems.map((li) => li?.expiryTime).filter(Boolean)
    : [];
  const expiresAtISO = pickMaxExpiryISO(expiries);

  const renewalState = d.renewalState || '';
  const willRenew =
    renewalState &&
    /RENEW/i.test(String(renewalState)) &&
    !/CANCEL|REVOKE/i.test(String(renewalState))
      ? true
      : undefined;

  const ackState = d.acknowledgementState || '';

  return {
    source: 'v2',
    active: ACTIVE_STATES_V2.has(state),
    willRenew,
    expiresAtISO,
    subscriptionState: state,
    acknowledgementState: ackState || undefined,
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
    acknowledgementState: d.acknowledgementState, // 0/1
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

async function sleep(ms) {
  await new Promise((r) => setTimeout(r, ms));
}

// Acknowledge helper (v1 endpoint; works even if we read v2).
async function acknowledgeIfNeeded(publisher, {
  packageName, productId, purchaseToken,
  normalized, force = false,
}) {
  // Need productId for v1 acknowledge; bail if missing
  if (!productId) {
    return { tried: false, ok: false, reason: 'no-productId' };
  }

  // Skip if package mismatch (защита от "чужих" токенов)
  if (PACKAGE_NAME && packageName && PACKAGE_NAME !== packageName) {
    return { tried: false, ok: false, reason: 'wrong-package' };
  }

  // Skip if already acknowledged
  if (isAckedValue(normalized.acknowledgementState)) {
    return { tried: false, ok: true, reason: 'already-acknowledged' };
  }

  // If only-when-active requested, but sub not active — skip
  if (!force && ACK_ONLY_IF_ACTIVE && !normalized.active) {
    return { tried: false, ok: false, reason: 'not-active' };
  }

  try {
    await publisher.purchases.subscriptions.acknowledge({
      packageName,
      subscriptionId: productId,
      token: purchaseToken,
      requestBody: { developerPayload: 'ack-by-server' },
    });
    return { tried: true, ok: true };
  } catch (e) {
    const msg = e?.message || String(e);
    // не ретраим заведомо «чужую» покупку
    if (/not owned by the user/i.test(msg)) {
      return { tried: true, ok: false, reason: 'not-owned', error: null };
    }
    return { tried: true, ok: false, error: msg };
  }
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
    ackOnVerify: ACK_ON_VERIFY,
    ackOnlyIfActive: ACK_ONLY_IF_ACTIVE,
    entitleWhileNotExpired: ENTITLE_WHILE_NOT_EXPIRED,
    entitleRequireAck: ENTITLE_REQUIRE_ACK,
    ackRefreshRetries: ACK_REFRESH_RETRIES,
    ackRefreshDelayMs: ACK_REFRESH_DELAY_MS,
    v: '1.3.0',
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

    // ===== DEBUG INPUT FROM CLIENT =====
    console.log('[IAP][VERIFY][INPUT]', {
      userId: userId || null,
      productId: productId || null,
      packageName_from_client: packageName || null,
      packageName_env: PACKAGE_NAME || null,
      pkg_effective: (packageName || PACKAGE_NAME) || null,
      purchaseToken_masked: purchaseToken ? maskToken(purchaseToken) : null,
      tokenLength: purchaseToken?.length ?? 0,
    });
    // ==================================

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

    // ---- Entitlement logic ----
    const expMs = Date.parse(normalized.expiresAtISO || '') || 0;
    const notExpired = Number.isFinite(expMs) && expMs > Date.now();

    let isAcked = isAckedValue(normalized.acknowledgementState);

    // Base rule: active if Google reports active
    let entitled = !!normalized.active;

    // Optional extension: entitled while not expired even if state=CANCELED
    if (!entitled && ENTITLE_WHILE_NOT_EXPIRED && notExpired) {
      entitled = true;
    }

    // Optional requirement: must be acknowledged
    if (ENTITLE_REQUIRE_ACK && entitled && !isAcked) {
      entitled = false;
    }

    // ---- ACK (server side) ----
    let ack = { tried: false, ok: false, reason: 'disabled' };
    if (ACK_ON_VERIFY) {
      ack = await acknowledgeIfNeeded(publisher, {
        packageName: pkg,
        productId,
        purchaseToken,
        normalized,
        force: !ACK_ONLY_IF_ACTIVE,
      });

      if (ack.tried) {
        console.log('[IAP] acknowledge attempt:', {
          tokenMasked: maskToken(purchaseToken),
          ok: ack.ok,
          reason: ack.reason || null,
          error: ack.error || null,
        });
      }

      // Если только что ack прошёл — дёрнем короткий re-fetch (V2 приоритетно)
      if (ack.ok && !isAcked) {
        for (let i = 0; i < ACK_REFRESH_RETRIES; i++) {
          await sleep(ACK_REFRESH_DELAY_MS);
          try {
            let refreshed;
            try {
              const v2r = await publisher.purchases.subscriptionsv2.get({
                packageName: pkg,
                token: purchaseToken,
              });
              refreshed = normalizeV2(v2r);
            } catch {
              if (productId) {
                const v1r = await publisher.purchases.subscriptions.get({
                  packageName: pkg,
                  subscriptionId: productId,
                  token: purchaseToken,
                });
                refreshed = normalizeV1(v1r);
              }
            }
            if (refreshed) {
              normalized = refreshed;
              isAcked = isAckedValue(refreshed.acknowledgementState);
              // Переоценим entitlement после ACK
              let ent2 = !!refreshed.active || (!!ENTITLE_WHILE_NOT_EXPIRED && notExpired);
              if (ENTITLE_REQUIRE_ACK && ent2 && !isAcked) ent2 = false;
              entitled = ent2;
              if (isAcked) break;
            }
          } catch {}
        }
      }
    }

    console.log('[IAP] verify ok:', {
      userId: userId || null,
      productId: productId || null,
      packageName: pkg,
      tokenMasked: maskToken(purchaseToken),
      source: normalized.source,
      subscriptionState: normalized.subscriptionState || null,
      acknowledgementState: normalized.acknowledgementState || null,
      willRenew: normalized.willRenew,
      expiresAt: normalized.expiresAtISO || null,
      notExpired,
      isAcked,
      entitled,
      pro: entitled, // alias
      policy: {
        entitleWhileNotExpired: ENTITLE_WHILE_NOT_EXPIRED,
        entitleRequireAck: ENTITLE_REQUIRE_ACK,
      },
      ackOnVerify: ACK_ON_VERIFY,
      ackOnlyIfActive: ACK_ONLY_IF_ACTIVE,
      ackTried: ack.tried,
      ackOk: ack.ok,
      ackReason: ack.reason || null,
      usedVersion: used,
    });

    res.json({
      ok: true,
      packageName: pkg,
      userId: userId || null,
      productId: productId || null,
      pro: !!entitled,
      entitled: !!entitled,
      notExpired,
      isAcked,
      ack: { tried: ack.tried, ok: ack.ok, reason: ack.reason || null },
      ...normalized,
      usedVersion: used,
    });
  } catch (err) {
    const code = err?.response?.status || 500;
    const data = err?.response?.data;

    // ===== DEBUG GOOGLE ERROR (expanded) =====
    console.error('[IAP][VERIFY][GOOGLE_ERROR]', {
      status: code,
      message: data?.error?.message || err?.message || null,
      // NOTE: log the raw errors array
      errors: data?.error?.errors || null,
    });
    if (Array.isArray(data?.error?.errors) && data.error.errors.length) {
      console.error('[IAP][VERIFY][GOOGLE_ERROR][0]', JSON.stringify(data.error.errors[0], null, 2));
    }
    // ========================================

    console.error('[IAP] verify error:', {
      status: code,
      message: err?.message,
      google: !!data,
      data: data || null,
    });

    res.status(code).json({
      ok: false,
      error: data || err?.message || 'Unknown error',
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
  console.log('      ACK_ON_VERIFY:', ACK_ON_VERIFY);
  console.log('      ACK_ONLY_IF_ACTIVE:', ACK_ONLY_IF_ACTIVE);
  console.log('      ENTITLE_WHILE_NOT_EXPIRED:', ENTITLE_WHILE_NOT_EXPIRED);
  console.log('      ENTITLE_REQUIRE_ACK:', ENTITLE_REQUIRE_ACK);
  console.log('      ACK_REFRESH_RETRIES:', ACK_REFRESH_RETRIES);
  console.log('      ACK_REFRESH_DELAY_MS:', ACK_REFRESH_DELAY_MS);
});
