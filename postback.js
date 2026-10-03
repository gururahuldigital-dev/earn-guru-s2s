const handlePubScalePostback = require('./pubscale');

module.exports = async function postback(req, res) {
  const body = req.body && typeof req.body === 'object' ? req.body : {};
  const query = req.query || {};
  const credential = body.token || body.auth_token || body.secret || body.signature ||
    query.token || query.auth_token || query.secret || query.signature;

  // Reuse the validated, idempotent handler; treat `signature` as a shared token
  // alias only. It does not verify provider-specific HMAC signatures.
  const forwardedRequest = Object.create(req);
  forwardedRequest.body = credential ? { ...body, token: credential } : body;
  forwardedRequest.query = query;

  let statusCode = 200;
  const forwardedResponse = {
    setHeader(name, value) {
      res.setHeader(name, value);
      return this;
    },
    status(code) {
      statusCode = code;
      return this;
    },
    json(payload) {
      const response = statusCode >= 200 && statusCode < 300 && payload?.ok
        ? { success: true }
        : payload;
      return res.status(statusCode).json(response);
    },
  };

  return handlePubScalePostback(forwardedRequest, forwardedResponse);
};
