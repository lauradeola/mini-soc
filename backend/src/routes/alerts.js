const express = require('express');
const db = require('../db');
const bus = require('../bus');
const { logAudit } = require('../audit');

const router = express.Router();
const list = db.prepare(`SELECT * FROM alerts ORDER BY ts DESC LIMIT ?`);
const one = db.prepare(`SELECT * FROM alerts WHERE id = ?`);
const history = db.prepare(`SELECT ts, username, text FROM alert_history WHERE alert_id = ? ORDER BY ts, id`);
const setStatus = db.prepare(`UPDATE alerts SET status = ? WHERE id = ?`);
const addHistory = db.prepare(`INSERT INTO alert_history (alert_id, ts, username, text) VALUES (?, ?, ?, ?)`);

const withHistory = (a) => ({ ...a, history: history.all(a.id) });

router.get('/', (req, res) => {
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 200);
  res.json(list.all(limit).map(withHistory));
});

// Fluxo de investigação: investigate | resolve | note
router.patch('/:id', (req, res) => {
  const alert = one.get(parseInt(req.params.id, 10));
  if (!alert) return res.status(404).json({ error: 'alerta não encontrado' });

  const { action, text } = req.body || {};
  let note;
  if (action === 'investigate') { setStatus.run('investigating', alert.id); note = 'Investigação iniciada'; }
  else if (action === 'resolve') { setStatus.run('resolved', alert.id); note = 'Marcado como resolvido'; }
  else if (action === 'note') {
    if (typeof text !== 'string' || !text.trim() || text.length > 140) return res.status(400).json({ error: 'nota inválida' });
    note = 'Nota: ' + text.trim();
  } else return res.status(400).json({ error: 'ação inválida' });

  addHistory.run(alert.id, Date.now(), req.user.username, note);
  logAudit(req.user.username, note, `${alert.type}, ${alert.ip}`);
  const updated = withHistory(one.get(alert.id));
  bus.emit('alert_update', updated);
  res.json(updated);
});

module.exports = router;
