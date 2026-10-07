const db = require('./db');
const bus = require('./bus');
const detectors = require('./detectors');
const { autoRespond } = require('./response');
const { notifyAlert } = require('./notify');

const isBlocked = db.prepare(`SELECT 1 FROM blocks WHERE ip = ? AND (expires_at IS NULL OR expires_at > ?)`);
const insertEvent = db.prepare(
  `INSERT INTO events (ts, ip, type, username, success, port) VALUES (?, ?, ?, ?, ?, ?)`
);

// Porta de entrada única dos eventos (API e simulador).
function ingest({ ip, type, username = null, success = false, port = null }) {
  if (isBlocked.get(ip, Date.now())) return { dropped: true, alerts: [] };

  const ev = { ts: Date.now(), ip, type, username, success: Boolean(success), port };
  const info = insertEvent.run(ev.ts, ev.ip, ev.type, ev.username, ev.success ? 1 : 0, ev.port);
  bus.emit('event', { id: Number(info.lastInsertRowid), ...ev });

  const alerts = detectors.map((d) => d(ev)).filter(Boolean);
  alerts.forEach((a) => {
    bus.emit('alert', a);
    autoRespond(a);
    notifyAlert(a).catch(() => {});
  });
  return { id: Number(info.lastInsertRowid), alerts };
}

module.exports = { ingest };
