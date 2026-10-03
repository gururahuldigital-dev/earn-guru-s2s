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

function firstValue(source, names) {
  for (const name of names) {
    const value = source?.[name];
    if (typeof value === 'string' && value.trim() !== '') return value.trim();
    if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  }
  return '';
}

function safeEqual(left, right) {
  const leftBuffer = Buffer.from(left, 'utf8');
  const rightBuffer = Buffer.from(right, 'utf8');
  return leftBuffer.length === rightBuffer.length &&
    crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function verifyBodyHmac(rawBody, signature, secret) {
  const hex = signature.replace(/^sha256=/i, '').trim();
  if (!/^[a-f0-9]{64}$/i.test(hex)) return false;
  const provided = Buffer.from(hex, 'hex');
  const expected = crypto.createHmac('sha256', secret).update(rawBody).digest();
  return provided.length === expected.length && crypto.timingSafeEqual(provided, expected);
}

async function readPostBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size > MAX_BODY_BYTES) {
      const error = new Error('Request body too large');
      error.statusCode = 413;
      throw error;
    }
    chunks.push(buffer);
  }

  const rawBody = Buffer.concat(chunks, size);
  if (rawBody.length === 0) return { rawBody, payload: req.body || {} };

  const contentType = req.headers?.['content-type']?.toLowerCase() || '';
  if (contentType.includes('application/x-www-form-urlencoded')) {
    return {
      rawBody,
      payload: Object.fromEntries(new URLSearchParams(rawBody.toString('utf8'))),
    };
  }
  if (!contentType.includes('application/json') && !contentType.includes('+json')) {
    const error = new Error('Unsupported content type');
    error.statusCode = 415;
    throw error;
  }

  let payload;
  try {
    payload = JSON.parse(rawBody.toString('utf8'));
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
  return { rawBody, payload };
}

module.exports = async function pubscalePostback(req, res) {
  if (req.method !== 'GET' && req.method !== 'POST') {
    res.setHeader('Allow', 'GET, POST');
    return respond(res, 405, { ok: false, error: 'method_not_allowed' });
  }

  const expectedToken = process.env.PUBSCALE_POSTBACK_TOKEN || '';
  const hmacSecret = process.env.PUBSCALE_POSTBACK_SECRET || '';
  if (!expectedToken && !hmacSecret) {
    logOutcome('configuration_error', { reason: 'postback_secret_missing' });
    return respond(res, 500, { ok: false, error: 'server_misconfigured' });
  }

  try {
    const query = req.query || {};
    let body = req.body && typeof req.body === 'object' ? req.body : {};
    let rawBody = Buffer.alloc(0);
    if (req.method === 'POST') {
      const parsed = await readPostBody(req);
      body = parsed.payload;
      rawBody = parsed.rawBody;
    }

    const authNames = ['token', 'tokan', 'auth_token', 'secret', 'signature'];
    const credentialCandidates = authNames.flatMap((name) => [
      firstValue(body, [name]),
      firstValue(query, [name]),
    ]).filter(Boolean);
    const headerSignature = firstValue(req.headers, [
      'x-pubscale-signature', 'x-signature',
    ]).replace(/^sha256=/i, '').trim();
    const bearerToken = (req.headers?.authorization || '').match(/^Bearer\s+(.+)$/i)?.[1] || '';
    const sharedCredentialValid = credentialCandidates.some((credential) =>
      safeEqual(credential, expectedToken));
    const hmacHeaderValid = req.method === 'POST' && headerSignature &&
      hmacSecret && verifyBodyHmac(rawBody, headerSignature, hmacSecret);

    if (!sharedCredentialValid && !hmacHeaderValid && !safeEqual(bearerToken, expectedToken)) {
      logOutcome('rejected', {
        reason: 'unauthorized',
        credentialProvided: Boolean(credentialCandidates.length || headerSignature || bearerToken),
        credentialConfigured: Boolean(expectedToken || hmacSecret),
      });
      return respond(res, 401, { ok: false, error: 'unauthorized' });
    }

    const userId = firstValue(body, ['user_id', 'userId', 'uid']) ||
      firstValue(query, ['user_id', 'userId', 'uid']);
    const transactionId = firstValue(body, [
      'transaction_id', 'transactionId', 'trans_id', 'tx_id', 'id',
    ]) || firstValue(query, [
      'transaction_id', 'transactionId', 'trans_id', 'tx_id', 'id',
    ]);
    const rewardValue = firstValue(body, [
      'value', 'reward', 'coins', 'amount', 'reward_value',
    ]) || firstValue(query, [
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
