const db = require('../db');
const rules = require('../rules');
const { raiseAlert } = require('../alerts');

const countUsers = db.prepare(
  `SELECT COUNT(DISTINCT username) AS n FROM events
   WHERE ip = ? AND type = 'login' AND success = 0 AND ts >= ?`
);

function checkCredStuffing(ev) {
  const r = rules.cred_stuffing;
  if (!r.on || ev.type !== 'login' || ev.success) return null;
  const { n } = countUsers.get(ev.ip, ev.ts - r.win * 1000);
  if (n < r.limit) return null;
  const sev = n >= r.limit * 3 ? 'critical' : 'high';
  return raiseAlert(ev, 'cred_stuffing', sev, n, `${n} usuários diferentes tentados em ${r.win}s`);
}

module.exports = { checkCredStuffing };
