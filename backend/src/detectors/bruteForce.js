const db = require('../db');
const rules = require('../rules');
const { raiseAlert } = require('../alerts');

const countFails = db.prepare(
  `SELECT COUNT(*) AS n FROM events WHERE ip = ? AND type = 'login' AND success = 0 AND ts >= ?`
);

function checkBruteForce(ev) {
  const r = rules.brute_force;
  if (!r.on || ev.type !== 'login' || ev.success) return null;
  const { n } = countFails.get(ev.ip, ev.ts - r.win * 1000);
  if (n < r.limit) return null;
  const sev = n >= r.limit * 4 ? 'critical' : n >= r.limit * 2 ? 'high' : 'medium';
  return raiseAlert(ev, 'brute_force', sev, n, `${n} falhas de login em ${r.win}s`);
}

module.exports = { checkBruteForce };
