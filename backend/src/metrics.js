const crypto = require('crypto');
const db = require('./db');
const bus = require('./bus');

const counters = { events: 0, alerts: {} };
let wsCount = () => 0;
bus.on('event', () => { counters.events++; });
bus.on('alert', (a) => { counters.alerts[a.type] = (counters.alerts[a.type] || 0) + 1; });

const activeBlocks = db.prepare('SELECT COUNT(*) AS n FROM blocks WHERE expires_at IS NULL OR expires_at > ?');

function render() {
  const out = [
    '# TYPE mini_soc_events_total counter', `mini_soc_events_total ${counters.events}`,
    '# TYPE mini_soc_alerts_total counter',
    ...Object.entries(counters.alerts).map(([t, n]) => `mini_soc_alerts_total{type="${t}"} ${n}`),
    '# TYPE mini_soc_blocks_active gauge', `mini_soc_blocks_active ${activeBlocks.get(Date.now()).n}`,
    '# TYPE mini_soc_ws_clients gauge', `mini_soc_ws_clients ${wsCount()}`,
    '# TYPE mini_soc_uptime_seconds gauge', `mini_soc_uptime_seconds ${Math.round(process.uptime())}`,
  ];
  return out.join('\n') + '\n';
}

// Formato Prometheus. Só existe quando METRICS_TOKEN está definido (Authorization: Bearer <token>).
function handler(req, res) {
  const token = process.env.METRICS_TOKEN;
  if (!token) return res.status(404).end();
  const given = Buffer.from((req.get('authorization') || '').replace(/^Bearer /, ''));
  const exp = Buffer.from(token);
  if (given.length !== exp.length || !crypto.timingSafeEqual(given, exp)) return res.status(401).end();
  res.type('text/plain; version=0.0.4').send(render());
}

module.exports = { handler, render, setWsCounter: (fn) => { wsCount = fn; } };
