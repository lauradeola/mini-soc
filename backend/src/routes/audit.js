const express = require('express');
const db = require('../db');
const { requireRole } = require('../auth');

const router = express.Router();
const list = db.prepare(`SELECT ts, username, action, detail FROM audit ORDER BY ts DESC, id DESC LIMIT 200`);

router.get('/', requireRole('admin'), (_req, res) => res.json(list.all()));

module.exports = router;
