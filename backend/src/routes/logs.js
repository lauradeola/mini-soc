const express = require('express');
const net = require('net');
const { ingest } = require('../ingest');

const router = express.Router();
const TYPES = new Set(['login', 'port_access']);

router.post('/', (req, res) => {
  const { ip, type, username = null, success = false, port = null } = req.body || {};

  if (typeof ip !== 'string' || !net.isIP(ip)) return res.status(400).json({ error: 'ip inválido' });
  if (!TYPES.has(type)) return res.status(400).json({ error: 'type inválido' });
  if (username !== null && (typeof username !== 'string' || username.length > 64)) {
    return res.status(400).json({ error: 'username inválido' });
  }
  if (port !== null && (!Number.isInteger(port) || port < 1 || port > 65535)) {
    return res.status(400).json({ error: 'port inválida' });
  }

  const r = ingest({ ip, type, username, success, port });
  if (r.dropped) return res.status(202).json({ dropped: true });
  res.status(201).json(r);
});

module.exports = router;
