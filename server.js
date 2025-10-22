/**
 * Minimal Google Play subscription verification server
 * ---------------------------------------------------
 * Запуск:
 *   cd iap-server
 *   npm i express googleapis body-parser
 *   $env:GOOGLE_APPLICATION_CREDENTIALS=".\\service-account.json"
 *   $env:PACKAGE_NAME="com.rosenbergvictor72.pealim2"
 *   node server.js
 *
 * Требования:
 * - service-account.json лежит рядом (или путь в переменной GOOGLE_APPLICATION_CREDENTIALS)
 * - Сервис-аккаунт выдан в Play Console → Settings → API access → Grant access
 *   Роль не ниже "View financial data", приложение выбрано в App permissions
 */

const express = require('express');
const bodyParser = require('body-parser');
const { google } = require('googleapis');

// ---------- Config ----------
const PORT = process.env.PORT || 3000;
const PACKAGE_NAME = process.env.PACKAGE_NAME || 'com.rosenbergvictor72.pealim2';

// Если файл ключа не указан через переменную, используем локальный
const KEYFILE_FALLBACK = process.env.GOOGLE_APPLICATION_CREDENTIALS || './service-account.json';

// Разрешить простой CORS (если хочешь звать с девайса в LAN)
const ENABLE_CORS = true;

// ---------- App ----------
const app = express();
app.use(bodyParser.json());

if (ENABLE_CORS) {
  app.use((_, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST,GET,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
    next();
  });
}

// Health / debug
app.get('/', (_req, res) => {
  res.json({
    ok: true,
    service: 'google-play-iap-verifier',
    packageName: PACKAGE_NAME,
    hasKeyFile: !!KEYFILE_FALLBACK,
  });
});

// ---------- Google auth helpers ----------
async function getAndroidPublisher() {
  const auth = new google.auth.GoogleAuth({
    scopes: ['https://www.googleapis.com/auth/androidpublisher'],
    keyFile: KEYFILE_FALLBACK, // если GOOGLE_APPLICATION_CREDENTIALS задана — она же здесь
  });
  const client = await auth.getClient();
  return google.androidpublisher({ version: 'v3', auth: client });
}

// ---------- Utils ----------
function toISO(ms) {
  if (!ms) return null;
  try {
    const n = Number(ms);
    if (!Number.isFinite(n)) return null;
    return new Date(n).toISOString();
  } catch {
    return null;
  }
}

/**
 * Унификация статуса из разных API
 * - v3 purchases.subscriptions.get: { paymentState, expiryTimeMillis, ... }
 * - v3 purchases.subscriptionsv2.get: { lineItems[], regionCode, ... }
 */
function normalizeV1(resp /* purchases.subscriptions.get */) {
  const expiryMs = resp?.data?.expiryTimeMillis ? Number(resp.data.expiryTimeMillis) : null;
  const canceled = !!resp?.data?.cancelReason; // 0..3
  const willRenew = resp?.data?.autoRenewing === true;
  const paymentState = resp?.data?.paymentState; // 0: pending, 1: received, 2: free trial, 3: pending deferred
  const intro = resp?.data?.introductoryPriceInfo ? true : false;

  const now = Date.now();
  const active = !!expiryMs && expiryMs > now;

  return {
    source: 'v1',
    active,
    willRenew,
    canceled,
    paymentState,
    isTrialOrIntro: intro || paymentState === 2,
    expiryTimeMillis: expiryMs || null,
    expiresAtISO: toISO(expiryMs),
    raw: resp?.data || null,
  };
}

function normalizeV2(resp /* purchases.subscriptionsv2.get */) {
  const d = resp?.data || {};
  // В v2 срок окончания ищем в lineItems[].expiryTime
  const li = Array.isArray(d.lineItems) ? d.lineItems[0] : null;
  const state = d.subscriptionState; // SUBSCRIPTION_STATE_ACTIVE / CANCELLED / IN_GRACE_PERIOD / PAUSED / EXPIRED
  const expiryMs =
    li?.expiryTime ? Number(li.expiryTime) : // иногда как millis
    li?.expiryTimeMillis ? Number(li.expiryTimeMillis) :
    null;

  const willRenew = d.renewalIntent === 'RENEWAL_INTENT_RENEW'
    || d.renewalIntent === 'RENEWAL_INTENT_UNSPECIFIED'; // best effort
  const canceled = state === 'SUBSCRIPTION_STATE_CANCELLED';
  const now = Date.now();
  const active = !!expiryMs && expiryMs > now && state !== 'SUBSCRIPTION_STATE_EXPIRED';

  // Определение trial/intro (best-effort): если первая фаза free
  const phases = li?.pricingPhases?.pricingPhase || li?.pricingPhases || [];
  let isTrialOrIntro = false;
  if (Array.isArray(phases) && phases.length) {
    const first = phases[0];
    const priceMicros = Number(first?.priceAmountMicros ?? 0);
    if (Number.isFinite(priceMicros) && priceMicros === 0) isTrialOrIntro = true;
  }

  return {
    source: 'v2',
    active,
    willRenew,
    canceled,
    state,
    isTrialOrIntro,
    expiryTimeMillis: expiryMs || null,
    expiresAtISO: toISO(expiryMs),
    raw: d,
  };
}

// ---------- Core endpoint ----------
/**
 * POST /iap/google/subscription/verify
 * Body: { userId, productId, packageName, purchaseToken }
 * - productId обязателен ТОЛЬКО для старого API v1 (fallback)
 * - рекомендуем в теле всегда передавать packageName = com.rosenbergvictor72.pealim2
 */
app.post('/iap/google/subscription/verify', async (req, res) => {
  try {
    const { userId, productId, packageName, purchaseToken } = req.body || {};
    const pkg = packageName || PACKAGE_NAME;

    if (!purchaseToken) {
      return res.status(400).json({ ok: false, error: 'purchaseToken is required' });
    }
    if (!pkg) {
      return res.status(400).json({ ok: false, error: 'packageName is required' });
    }

    const publisher = await getAndroidPublisher();

    // 1) Пытаемся через V2 (новый API, не требует productId)
    let norm = null;
    try {
      const v2 = await publisher.purchases.subscriptionsv2.get({
        packageName: pkg,
        token: purchaseToken,
      });
      norm = normalizeV2(v2);
    } catch (e) {
      // если токен создан старым API/планом — fallback на V1
      // console.log('[verify] v2 failed — fallback to v1:', e?.response?.data || e?.message);
    }

    // 2) Если V2 не сработал, пробуем V1 (нужно знать productId = SKU)
    if (!norm) {
      if (!productId) {
        return res.status(400).json({
          ok: false,
          error: 'productId is required for v1 fallback',
          hint: 'Передайте productId (SKU), например "monthly_ils_10", или используйте v2 token.',
        });
      }
      const v1 = await publisher.purchases.subscriptions.get({
        packageName: pkg,
        subscriptionId: productId,
        token: purchaseToken,
      });
      norm = normalizeV1(v1);
    }

    // Решение о предоставлении доступа
    const pro = !!norm.active;

    // Можно дополнительно сохранить в БД userId → expiresAt и т.п.
    // await db.users.update(userId, { pro, expiresAt: norm.expiresAtISO, ... })

    res.json({
      ok: true,
      packageName: pkg,
      userId: userId || null,
      productId: productId || null,
      pro,
      ...norm,
    });
  } catch (err) {
    const code = err?.response?.status || 500;
    res.status(code).json({
      ok: false,
      error: err?.response?.data || err?.message || 'Unknown error',
    });
  }
});

// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`[IAP] Verification server running on port ${PORT}`);
  console.log(`      Package: ${PACKAGE_NAME}`);
  console.log(`      Key: ${KEYFILE_FALLBACK}`);
});
