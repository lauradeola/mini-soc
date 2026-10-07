const express = require('express');
const net = require('net');
const db = require('../db');
const bus = require('../bus');
const { requireRole } = require('../auth');
const { logAudit } = require('../audit');
const { blockIp } = require('../response');

const router = express.Router();
const list = db.prepare(`SELECT ip, ts, reason, expires_at, blocked_by FROM blocks ORDER BY ts DESC`);
const remove = db.prepare(`DELETE FROM blocks WHERE ip = ?`);

router.get('/', (_req, res) => res.json(list.all()));

router.post('/', requireRole('admin'), (req, res) => {
  const { ip, reason = '', minutes = null } = req.body || {};
  if (typeof ip !== 'string' || !net.isIP(ip)) return res.status(400).json({ error: 'ip inválido' });
  if (typeof reason !== 'string' || reason.length > 64) return res.status(400).json({ error: 'motivo inválido' });
  const mins = minutes === null ? null : Math.min(1440, Math.max(1, Math.round(Number(minutes)) || 1));
  const block = blockIp(ip, reason, { minutes: mins, by: req.user.username });
  if (!block) return res.status(409).json({ error: 'este IP está na lista de exceções e não pode ser bloqueado' });
  logAudit(req.user.username, 'IP bloqueado', `${ip}, ${reason}`);
  res.status(201).json(block);
});

router.delete('/:ip', requireRole('admin'), (req, res) => {
  if (!net.isIP(req.params.ip)) return res.status(400).json({ error: 'ip inválido' });
  remove.run(req.params.ip);
  logAudit(req.user.username, 'IP desbloqueado', req.params.ip);
  bus.emit('unblock', { ip: req.params.ip });
  res.status(204).end();
});

module.exports = router;
