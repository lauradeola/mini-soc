const express = require('express');
const { requireRole } = require('../auth');
const { logAudit } = require('../audit');
const keys = require('../apikeys');

const router = express.Router();
router.use(requireRole('admin'));

router.get('/', (_req, res) => res.json(keys.list()));

// A resposta traz a chave completa uma única vez
router.post('/', (req, res) => {
  const name = req.body && req.body.name;
  if (typeof name !== 'string' || name.trim().length < 2 || name.length > 40) {
    return res.status(400).json({ error: 'dê um nome de 2 a 40 caracteres para a fonte' });
  }
  const created = keys.create(name.trim());
  logAudit(req.user.username, 'Chave de API criada', created.name);
  res.status(201).json(created);
});

router.delete('/:id', (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!keys.revoke(id)) return res.status(404).json({ error: 'chave não encontrada' });
  logAudit(req.user.username, 'Chave de API revogada', String(id));
  res.status(204).end();
});

module.exports = router;
