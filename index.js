/**
 * request-anomaly-guard
 * ---------------------
 * Express middleware that flags anomalous HTTP request patterns:
 *  - request-body size well above the moving average
 *  - unusual header combinations
 *  - rapid bursts from a single IP
 *
 * Install: npm install request-anomaly-guard
 * Usage:   app.use(require('request-anomaly-guard')())
 */

const events = require('events');

const DEFAULT_LIMITS = {
  maxBodyBytes: 1_000_000,   // 1MB absolute cap
  burstWindowMs: 10_000,     // count requests in this window
  burstMax: 60,              // max requests per window per IP
};

class AnomalyDetector extends events.EventEmitter {
  constructor(opts = {}) {
    super();
    this.limits = { ...DEFAULT_LIMITS, ...opts.limits };
    this.ipStats = new Map(); // ip -> { count, windowStart, sizes: [] }
  }

  _statsFor(ip) {
    const now = Date.now();
    let s = this.ipStats.get(ip);
    if (!s || now - s.windowStart > this.limits.burstWindowMs) {
      s = { count: 0, windowStart: now, sizes: [] };
      this.ipStats.set(ip, s);
    }
    return s;
  }

  detect(req) {
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    const s = this._statsFor(ip);
    s.count += 1;
    const len = Number(req.headers['content-length'] || 0);
    s.sizes.push(len);
    if (s.sizes.length > 50) s.sizes.shift();

    const avgSize = s.sizes.length
      ? s.sizes.reduce((a, b) => a + b, 0) / s.sizes.length
      : 0;

    const reasons = [];

    // 1. Burst: too many requests from one IP in the window
    if (s.count > this.limits.burstMax) {
      reasons.push(`burst: ${s.count} reqs in ${this.limits.burstWindowMs / 1000}s`);
    }

    // 2. Body size: way above this IP's own moving average
    if (len > this.limits.maxBodyBytes) {
      reasons.push(`oversized body: ${len} bytes (cap ${this.limits.maxBodyBytes})`);
    } else if (avgSize > 0 && len > avgSize * 10 && len > 10_000) {
      reasons.push(`anomalous body: ${len} bytes vs ${Math.round(avgSize)} avg`);
    }

    // 3. Suspicious headers
    const ua = req.headers['user-agent'] || '';
    if (/^(curl|wget|python-requests|httpie)\/?/i.test(ua) && !req.headers['x-client-version']) {
      reasons.push(`bare client UA: ${ua}`);
    }

    if (reasons.length) {
      const anomaly = { ip, reasons, bodyBytes: len, timestamp: now };
      this.emit('anomaly', anomaly, req);
      return anomaly;
    }
    return null;
  }

  middleware(opts = {}) {
    const onAnomaly = opts.onAnomaly || ((req, res, anomaly) => {
      res.status(403).json({ error: 'request blocked by anomaly guard', reasons: anomaly.reasons });
    });
    return (req, res, next) => {
      const anomaly = this.detect(req);
      if (anomaly) return onAnomaly(req, res, anomaly);
      next();
    };
  }
}

module.exports = { AnomalyDetector, createGuard: (opts) => new AnomalyDetector(opts).middleware() };
