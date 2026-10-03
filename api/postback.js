const handlePubScalePostback = require('./pubscale');

module.exports = handlePubScalePostback;
module.exports.config = {
  api: { bodyParser: false },
};
