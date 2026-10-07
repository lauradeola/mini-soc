const db = require('../db');
const rules = require('../rules');
const { raiseAlert } = require('../alerts');

const countPorts = db.prepare(
  `SELECT COUNT(DISTINCT port) AS n FROM events WHERE ip = ? AND type = 'port_access' AND ts >= ?`
);

function checkPortScan(ev) {
  const r = rules.port_scan;
  if (!r.on || ev.type !== 'port_access') return null;
  const { n } = countPorts.get(ev.ip, ev.ts - r.win * 1000);
  if (n < r.limit) return null;
  const sev = n >= r.limit * 2.5 ? 'critical' : 'high';
  return raiseAlert(ev, 'port_scan', sev, n, `${n} portas diferentes em ${r.win}s`);
}

module.exports = { checkPortScan };
