const express = require('express');
const settings = require('../settings');
const { configured } = require('../notify');
const { requireRole } = require('../auth');
const { logAudit } = require('../audit');
const { save } = require('../config');

const router = express.Router();
const view = () => ({
  autoBlock: settings.autoBlock,
  allowlist: settings.allowlist(),
  notifications: { configured: configured() },
});

router.get('/', (_req, res) => res.json(view()));

router.put('/', requireRole('admin'), (req, res) => {
  const a = req.body && req.body.autoBlock;
  if (a && typeof a === 'object') {
    if (typeof a.on === 'boolean') settings.autoBlock.on = a.on;
    if (Number.isFinite(Number(a.minutes))) settings.autoBlock.minutes = Math.min(1440, Math.max(1, Math.round(Number(a.minutes))));
  }
  save('settings', settings);
  logAudit(req.user.username, 'Resposta automática alterada', JSON.stringify(settings.autoBlock));
  res.json(view());
});

module.exports = router;
