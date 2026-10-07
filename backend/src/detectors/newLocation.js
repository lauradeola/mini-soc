const db = require('../db');
const rules = require('../rules');
const { raiseAlert } = require('../alerts');

const known = db.prepare(`SELECT COUNT(*) AS n FROM user_ips WHERE username = ?`);
const seen = db.prepare(`SELECT 1 FROM user_ips WHERE username = ? AND ip = ?`);
const remember = db.prepare(`INSERT OR IGNORE INTO user_ips (username, ip, first_seen) VALUES (?, ?, ?)`);

// Primeiro login de uma conta vindo de um IP que ela nunca usou (só avisa se a conta já tem histórico)
function checkNewIp(ev) {
  if (ev.type !== 'login' || !ev.success || !ev.username) return null;
  const isNew = !seen.get(ev.username, ev.ip);
  const { n } = known.get(ev.username);
  if (isNew) remember.run(ev.username, ev.ip, ev.ts); // aprende sempre, mesmo com a regra desligada
  const r = rules.new_ip;
  if (!r.on || !isNew || n < r.limit) return null;
  return raiseAlert(ev, 'new_ip', 'medium', n, `Primeiro login de "${ev.username}" vindo deste IP (a conta já usou ${n})`);
}

module.exports = { checkNewIp };
