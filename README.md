# request-anomaly-guard

Express middleware that detects anomalous HTTP request patterns and blocks them before they hit your route handlers.

## What it catches

- **Request-body bursts** — a single IP sending far more requests than its own baseline
- **Oversized bodies** — payloads above an absolute cap or far above the moving average
- **Suspicious clients** — bare curl/wget/python-requests UAs without an identifying header

## Install

```bash
npm install request-anomaly-guard
```

## Usage

```js
const express = require('express');
const { createGuard } = require('request-anomaly-guard');

const app = express();

app.use(createGuard({
  limits: { maxBodyBytes: 500_000, burstMax: 30 },
  onAnomaly: (req, res, anomaly) => {
    console.log('blocked:', anomaly.reasons);
    res.status(403).json({ error: 'anomalous request', reasons: anomaly.reasons });
  },
}));

app.post('/submit', (req, res) => res.json({ ok: true }));

app.listen(3000);
```

## API

`createGuard(opts)` returns Express middleware.

- `opts.limits.maxBodyBytes` — absolute body-size cap (default `1_000_000`)
- `opts.limits.burstWindowMs` — burst counting window (default `10_000`)
- `opts.limits.burstMax` — max requests per window per IP (default `60`)
- `opts.onAnomaly(req, res, anomaly)` — called when a request is flagged; default responds `403`

The guard also extends `EventEmitter`, so you can listen for `anomaly` events for logging/metrics.

## License

MIT
