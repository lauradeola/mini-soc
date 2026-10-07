const express = require('express');
const net = require('net');
const db = require('../db');
const { reputation } = require('../reputation');
const { geo } = require('../geo');

const router = express.Router();
const events = db.prepare(`SELECT ts, ip, type, username, success, port FROM events WHERE ip = ? ORDER BY ts DESC LIMIT 40`);
const totals = db.prepare(
  `SELECT COUNT(*) AS events,
          COALESCE(SUM(CASE WHEN type = 'login' AND success = 0 THEN 1 ELSE 0 END), 0) AS failures
   FROM events WHERE ip = ?`
);

// Ficha do IP: eventos recentes, totais e reputação (se houver chave do AbuseIPDB)
router.get('/:ip', async (req, res) => {
  const ip = req.params.ip;
  if (!net.isIP(ip)) return res.status(400).json({ error: 'ip inválido' });
  const [rep, where] = await Promise.all([reputation(ip), geo(ip)]);
  res.json({ ip, events: events.all(ip), totals: totals.get(ip), reputation: rep, geo: where });
});

module.exports = router;
