const express = require('express');
const rules = require('../rules');
const { requireRole } = require('../auth');
const { logAudit } = require('../audit');
const { save } = require('../config');

const router = express.Router();
const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, Math.round(v)));

router.get('/', (_req, res) => res.json(rules));

router.put('/', requireRole('admin'), (req, res) => {
  const body = req.body || {};
  for (const key of Object.keys(rules)) {
    const r = body[key];
    if (!r || typeof r !== 'object') continue;
    if (typeof r.on === 'boolean') rules[key].on = r.on;
    if (Number.isFinite(Number(r.limit))) rules[key].limit = clamp(Number(r.limit), 2, 100);
    if (Number.isFinite(Number(r.win))) rules[key].win = clamp(Number(r.win), 10, 300);
  }
  save('rules', rules);
  logAudit(req.user.username, 'Regras alteradas', JSON.stringify(rules));
  res.json(rules);
});

module.exports = router;
