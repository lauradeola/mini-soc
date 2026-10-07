const db = require('./db');

const COOLDOWN_MS = 60_000;
const NAMES = { brute_force: 'Força bruta', cred_stuffing: 'Credential stuffing', compromise: 'Acesso após falhas', new_ip: 'Login de novo IP', off_hours: 'Login fora do horário', port_scan: 'Varredura de portas' };

const lastAlert = db.prepare(`SELECT ts FROM alerts WHERE ip = ? AND type = ? ORDER BY ts DESC LIMIT 1`);
const otherCredAlert = db.prepare(
  `SELECT 1 FROM alerts
   WHERE ip = ? AND type IN ('brute_force', 'cred_stuffing') AND type != ? AND ts >= ? LIMIT 1`
);
const insertAlert = db.prepare(
  `INSERT INTO alerts (ts, type, severity, ip, message, count) VALUES (?, ?, ?, ?, ?, ?)`
);
const addHistory = db.prepare(`INSERT INTO alert_history (alert_id, ts, username, text) VALUES (?, ?, ?, ?)`);

// Cria o alerta, respeitando o cooldown por IP e regra. Força bruta e credential
// stuffing não disparam juntos para o mesmo IP: vale o primeiro que aparecer.
function raiseAlert(ev, type, severity, count, message) {
  const last = lastAlert.get(ev.ip, type);
  if (last && ev.ts - last.ts < COOLDOWN_MS) return null;
  if ((type === 'brute_force' || type === 'cred_stuffing') && otherCredAlert.get(ev.ip, type, ev.ts - COOLDOWN_MS)) return null;

  const alert = { ts: ev.ts, type, severity, ip: ev.ip, message, count };
  const info = insertAlert.run(alert.ts, alert.type, alert.severity, alert.ip, alert.message, alert.count);
  const id = Number(info.lastInsertRowid);
  const text = 'Alerta gerado pela regra ' + NAMES[type];
  addHistory.run(id, alert.ts, 'sistema', text);
  return { id, ...alert, status: 'open', history: [{ ts: alert.ts, username: 'sistema', text }] };
}

module.exports = { raiseAlert };
