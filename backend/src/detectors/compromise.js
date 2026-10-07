const db = require('../db');
const rules = require('../rules');
const { raiseAlert } = require('../alerts');

const countFails = db.prepare(
  `SELECT COUNT(*) AS n FROM events WHERE ip = ? AND type = 'login' AND success = 0 AND ts >= ?`
);

// O sinal mais grave: o atacante errou várias vezes e depois entrou
function checkCompromise(ev) {
  const r = rules.compromise;
  if (!r.on || ev.type !== 'login' || !ev.success) return null;
  const { n } = countFails.get(ev.ip, ev.ts - r.win * 1000);
  if (n < r.limit) return null;
  return raiseAlert(ev, 'compromise', 'critical', n, `Login de ${ev.username} bem-sucedido após ${n} falhas em ${r.win}s`);
}

module.exports = { checkCompromise };
