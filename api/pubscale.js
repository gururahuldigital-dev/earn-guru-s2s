const crypto = require('node:crypto');
const { initializeApp, getApps, cert } = require('firebase-admin/app');
const { getFirestore, FieldValue } = require('firebase-admin/firestore');

const MAX_BODY_BYTES = 1024 * 1024;
const MAX_REWARD_COINS = 10_000_000;

function getDb() {
  if (!getApps().length) {
    const serviceAccountJson = process.env.FIREBASE_SERVICE_ACCOUNT;
    if (!serviceAccountJson) {
      throw new Error('FIREBASE_SERVICE_ACCOUNT is not configured');
    }

    const serviceAccount = JSON.parse(serviceAccountJson);
    if (serviceAccount.private_key) {
      serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, '\n');
    }
    initializeApp({ credential: cert(serviceAccount) });
  }
  return getFirestore();
}

function respond(res, status, payload) {
  res.setHeader('Cache-Control', 'no-store');
  return res.status(status).json(payload);
}

function logOutcome(outcome, details = {}) {
  console.info('[pubscale-postback]', JSON.stringify({ outcome, ...details }));
}

async function readRawBody(req) {
  const chunks = [];
  let totalBytes = 0;

  for await (const chunk of req) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    totalBytes += buffer.length;
    if (totalBytes > MAX_BODY_BYTES) {
      const error = new Error('Request body too large');
      error.statusCode = 413;
      throw error;
    }
    chunks.push(buffer);
  }

  return Buffer.concat(chunks, totalBytes);
}

function getSignature(req) {
  const value = req.headers?.['x-pubscale-signature'] ||
    req.headers?.['x-signature'];
  if (Array.isArray(value)) return value[0] || '';
  return typeof value === 'string' ? value.trim() : '';
}

function verifySignature(rawBody, suppliedSignature, secret) {
  const signatureHex = suppliedSignature.replace(/^sha256=/i, '').trim();
  if (!/^[a-f0-9]{64}$/i.test(signatureHex)) return false;

  const suppliedDigest = Buffer.from(signatureHex, 'hex');
  const expectedDigest = crypto
    .createHmac('sha256', secret)
    .update(rawBody)
    .digest();

  return suppliedDigest.length === expectedDigest.length &&
    crypto.timingSafeEqual(suppliedDigest, expectedDigest);
}

function parsePayload(rawBody, contentType = '') {
  const type = contentType.toLowerCase();
  const text = rawBody.toString('utf8');

  if (type.includes('application/x-www-form-urlencoded')) {
    return Object.fromEntries(new URLSearchParams(text));
  }
  if (!type.includes('application/json') && !type.includes('+json')) {
    const error = new Error('Unsupported content type');
    error.statusCode = 415;
    throw error;
  }

  let payload;
  try {
    payload = JSON.parse(text);
  } catch (_) {
    const error = new Error('Malformed JSON body');
    error.statusCode = 400;
    throw error;
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    const error = new Error('JSON body must be an object');
    error.statusCode = 400;
    throw error;
  }
  return payload;
}

function firstValue(source, names) {
  for (const name of names) {
    const value = source?.[name];
    if (typeof value === 'string' && value.trim() !== '') return value.trim();
    if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  }
  return '';
}

module.exports = async function pubscalePostback(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return respond(res, 405, { ok: false, error: 'method_not_allowed' });
  }

  const signatureSecret = process.env.PUBSCALE_POSTBACK_SECRET || '';
  if (!signatureSecret) {
    logOutcome('configuration_error', { reason: 'signature_secret_missing' });
    return respond(res, 500, { ok: false, error: 'server_misconfigured' });
  }

  try {
    const rawBody = await readRawBody(req);
    const signature = getSignature(req);
    if (!signature || !verifySignature(rawBody, signature, signatureSecret)) {
      logOutcome('rejected', {
        reason: 'invalid_signature',
        signatureProvided: Boolean(signature),
      });
      return respond(res, 401, { ok: false, error: 'invalid_signature' });
    }

    const payload = parsePayload(rawBody, req.headers?.['content-type'] || '');
    const userId = firstValue(payload, ['user_id', 'userId', 'uid']);
    const transactionId = firstValue(payload, [
      'transaction_id', 'transactionId', 'trans_id', 'tx_id', 'id',
    ]);
    const rewardValue = firstValue(payload, [
      'value', 'reward', 'coins', 'amount', 'reward_value',
    ]);
    const rewardCoins = Number(rewardValue);

    if (!userId || userId.length > 1500 || userId.includes('/') ||
        !transactionId || transactionId.length > 500 ||
        !Number.isSafeInteger(rewardCoins) || rewardCoins < 1 ||
        rewardCoins > MAX_REWARD_COINS) {
      logOutcome('rejected', {
        reason: 'invalid_parameters',
        userIdProvided: Boolean(userId),
        transactionIdProvided: Boolean(transactionId),
        rewardProvided: Boolean(rewardValue),
        rewardIsPositiveInteger: Number.isSafeInteger(rewardCoins) && rewardCoins > 0,
      });
      return respond(res, 400, { ok: false, error: 'invalid_parameters' });
    }

    const db = getDb();
    const userRef = db.collection('users').doc(userId);
    const transactionKey = crypto.createHash('sha256')
      .update(transactionId, 'utf8')
      .digest('hex');
    const postbackRef = db.collection('pubscale_postbacks').doc(transactionKey);

    const outcome = await db.runTransaction(async (transaction) => {
      const previous = await transaction.get(postbackRef);
      if (previous.exists) {
        const previousData = previous.data();
        if (previousData.userId !== userId || previousData.coins !== rewardCoins) {
          return 'transaction_conflict';
        }
        return 'duplicate';
      }

      const userSnapshot = await transaction.get(userRef);
      if (!userSnapshot.exists) return 'user_not_found';

      transaction.update(userRef, { coins: FieldValue.increment(rewardCoins) });
      transaction.set(userRef.collection('earnings').doc(transactionKey), {
        title: 'PubScale Offer Reward',
        coins: rewardCoins,
        category: 'pubscale_offerwall',
        source: 'pubscale',
        transactionId,
        timestamp: FieldValue.serverTimestamp(),
      });
      transaction.set(userRef.collection('transactions').doc(transactionKey), {
        title: 'PubScale Offer Reward',
        coins: rewardCoins,
        type: 'credit',
        category: 'pubscale_offerwall',
        source: 'pubscale',
        transactionId,
        createdAt: FieldValue.serverTimestamp(),
      });
      transaction.create(postbackRef, {
        userId,
        coins: rewardCoins,
        transactionId,
        creditedAt: FieldValue.serverTimestamp(),
      });
      return 'credited';
    });

    if (outcome === 'user_not_found') {
      logOutcome('rejected', { reason: outcome });
      return respond(res, 404, { ok: false, error: 'user_not_found' });
    }
    if (outcome === 'transaction_conflict') {
      logOutcome('rejected', { reason: outcome });
      return respond(res, 409, { ok: false, error: 'transaction_conflict' });
    }

    logOutcome(outcome, { transactionKey, rewardCoins });
    return respond(res, 200, { ok: true, status: outcome });
  } catch (error) {
    const statusCode = error.statusCode || 500;
    if (statusCode >= 500) {
      console.error('[pubscale-postback] processing_failed', {
        code: error?.code || null,
        name: error?.name || 'Error',
        message: error?.message || 'Unknown error',
      });
    } else {
      logOutcome('rejected', { reason: error.message, statusCode });
    }
    return respond(res, statusCode, {
      ok: false,
      error: statusCode === 500 ? 'internal_error' : 'invalid_request',
    });
  }
};

module.exports.config = {
  api: { bodyParser: false },
};
