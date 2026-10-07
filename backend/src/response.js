const db = require('./db');
const bus = require('./bus');
const settings = require('./settings');
const { logAudit } = require('./audit');

const upsert = db.prepare(
  `INSERT INTO blocks (ip, ts, reason, expires_at, blocked_by) VALUES (?, ?, ?, ?, ?)
   ON CONFLICT(ip) DO UPDATE SET ts = excluded.ts, reason = excluded.reason,
     expires_at = excluded.expires_at, blocked_by = excluded.blocked_by`
);
const expired = db.prepare(`SELECT ip FROM blocks WHERE expires_at IS NOT NULL AND expires_at <= ?`);
const remove = db.prepare(`DELETE FROM blocks WHERE ip = ?`);

// Bloqueia um IP (por `minutes` minutos, ou sem prazo). IPs da ALLOWLIST nunca são bloqueados: devolve null.
function blockIp(ip, reason, { minutes = null, by = 'sistema' } = {}) {
  if (settings.allowlist().includes(ip)) return null;
  const ts = Date.now();
  const expires_at = minutes ? ts + minutes * 60_000 : null;
  upsert.run(ip, ts, reason, expires_at, by);
  const block = { ip, ts, reason, expires_at, blocked_by: by };
  bus.emit('block', block);
  return block;
}

// Resposta automática: bloqueia o IP de todo alerta crítico, se estiver ligada
function autoRespond(alert) {
  const a = settings.autoBlock;
  if (!a.on || alert.severity !== 'critical') return null;
  const block = blockIp(alert.ip, alert.type, { minutes: a.minutes, by: 'sistema' });
  if (block) logAudit('sistema', 'Bloqueio automático', `${alert.ip}, ${alert.type}, ${a.minutes} min`);
  return block;
}

// Libera os bloqueios que já venceram
function sweep() {
  for (const { ip } of expired.all(Date.now())) {
    remove.run(ip);
    logAudit('sistema', 'Bloqueio expirado', ip);
    bus.emit('unblock', { ip });
  }
}

module.exports = { blockIp, autoRespond, sweep };
