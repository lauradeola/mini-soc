const express = require('express');
const simulator = require('../simulator');

const router = express.Router();

// Só existe quando SIMULATE=true (ambiente de demonstração)
router.post('/', (req, res) => {
  if (process.env.SIMULATE !== 'true') return res.status(404).json({ error: 'simulação desligada neste servidor' });
  const kind = req.body && req.body.kind;
  if (!['brute', 'stuff', 'scan', 'comp'].includes(kind)) return res.status(400).json({ error: 'kind inválido' });
  simulator.burst(kind);
  res.status(202).json({ started: kind });
});

module.exports = router;
