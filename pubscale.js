const crypto = require('node:crypto');
const { initializeApp, getApps, cert } = require('firebase-admin/app');
const { getFirestore, FieldValue } = require('firebase-admin/firestore');

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

function respond(res, status, payload) {
  res.setHeader('Cache-Control', 'no-store');
  return res.status(status).json(payload);
}

function logOutcome(outcome, details = {}) {
  console.info('[pubscale-postback]', JSON.stringify({ outcome, ...details }));
}

module.exports = async function pubscalePostback(req, res) {
  if (req.method !== 'GET' && req.method !== 'POST') {
    res.setHeader('Allow', 'GET, POST');
    return respond(res, 405, { ok: false, error: 'method_not_allowed' });
  }

  try {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const query = req.query || {};
    const authorization = req.headers?.authorization || '';
    const bearerToken = authorization.match(/^Bearer\s+(.+)$/i)?.[1] || '';
    const suppliedToken = firstValue(body, ['token', 'auth_token', 'secret']) ||
      firstValue(query, ['token', 'auth_token', 'secret']) || bearerToken;
    const expectedToken = process.env.PUBSCALE_POSTBACK_TOKEN || '';

    if (!expectedToken || !suppliedToken || !safeEqual(suppliedToken, expectedToken)) {
      logOutcome('rejected', {
        reason: 'unauthorized',
        tokenConfigured: Boolean(expectedToken),
        tokenProvided: Boolean(suppliedToken),
      });
      return respond(res, 401, { ok: false, error: 'unauthorized' });
    }

    const userIdFromBody = firstValue(body, ['user_id', 'userId', 'uid']);
    const userIdFromQuery = firstValue(query, ['user_id', 'userId', 'uid']);
    const userId = userIdFromBody || userIdFromQuery;

    let transactionId = firstValue(body, ['transaction_id', 'transactionId', 'trans_id', 'tx_id', 'id']) ||
      firstValue(query, ['transaction_id', 'transactionId', 'trans_id', 'tx_id', 'id']);
    
    // Fallback if transactionId is missing from test panel
    if (!transactionId) {
      transactionId = 'test_tx_' + Date.now() + '_' + Math.random().toString(36).substring(2, 7);
    }

    const rewardFromBody = firstValue(body, ['value', 'reward', 'coins', 'amount', 'reward_value']);
    const rewardFromQuery = firstValue(query, ['value', 'reward', 'coins', 'amount', 'reward_value']);
    const rewardValue = rewardFromBody || rewardFromQuery;
    const rewardCoins = Number(rewardValue);
    
    const parameterSources = {
      userId: userIdFromBody ? 'body' : (userIdFromQuery ? 'query' : 'missing'),
      transactionId: transactionId ? 'auto_or_provided' : 'missing',
      reward: rewardFromBody ? 'body' : (rewardFromQuery ? 'query' : 'missing'),
    };

    if (!userId || userId.length > 1500 || userId.includes('/') ||
        !Number.isSafeInteger(rewardCoins) || rewardCoins < 1 ||
        rewardCoins > MAX_REWARD_COINS) {
      logOutcome('rejected', {
        reason: 'invalid_parameters',
        userIdProvided: Boolean(userId),
        rewardProvided: Boolean(rewardValue),
        rewardIsPositiveInteger: Number.isSafeInteger(rewardCoins) && rewardCoins > 0,
        parameterSources,
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
    logOutcome(outcome, {
      transactionKey,
      rewardCoins,
      parameterSources,
    });
    return respond(res, 200, { ok: true, status: outcome });
  } catch (error) {
    console.error('[pubscale-postback] processing_failed', {
      code: error?.code || null,
      name: error?.name || 'Error',
      message: error?.message || 'Unknown error',
    });
    return respond(res, 500, { ok: false, error: 'internal_error' });
  }
};