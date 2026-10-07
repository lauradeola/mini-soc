const express = require('express');
const db = require('../db');
const { hashPassword, requireRole } = require('../auth');
const { logAudit } = require('../audit');

const router = express.Router();
router.use(requireRole('admin'));

const NAME = /^[a-z0-9_.-]{3,32}$/;
const list = db.prepare(`SELECT username, role, created_at, locked_until FROM users ORDER BY username`);
const unlock = db.prepare(`UPDATE users SET failed_logins = 0, locked_until = NULL WHERE username = ?`);
const find = db.prepare(`SELECT username, role FROM users WHERE username = ?`);
const admins = db.prepare(`SELECT COUNT(*) AS n FROM users WHERE role = 'admin'`);
const insert = db.prepare(`INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)`);
// Trocar a senha também derruba as sessões abertas e destrava a conta
const setPass = db.prepare(`UPDATE users SET password_hash = ?, token_version = token_version + 1, failed_logins = 0, locked_until = NULL WHERE username = ?`);
const remove = db.prepare(`DELETE FROM users WHERE username = ?`);
const goodPassword = (p) => typeof p === 'string' && p.length >= 10 && p.length <= 128;

router.get('/', (_req, res) => res.json(list.all().map(({ locked_until, ...u }) => ({ ...u, locked: !!locked_until && locked_until > Date.now() }))));

router.post('/', (req, res) => {
  const { username, password, role } = req.body || {};
  if (typeof username !== 'string' || !NAME.test(username)) return res.status(400).json({ error: 'usuário: 3 a 32 caracteres (letras minúsculas, números, . _ -)' });
  if (!goodPassword(password)) return res.status(400).json({ error: 'a senha precisa ter de 10 a 128 caracteres' });
  if (role !== 'admin' && role !== 'analyst') return res.status(400).json({ error: 'perfil inválido' });
  if (find.get(username)) return res.status(409).json({ error: 'esse usuário já existe' });
  insert.run(username, hashPassword(password), role, Date.now());
  logAudit(req.user.username, 'Usuário criado', `${username}, ${role}`);
  res.status(201).json({ username, role });
});

router.patch('/:username', (req, res) => {
  if (!find.get(req.params.username)) return res.status(404).json({ error: 'usuário não encontrado' });
  if (!goodPassword(req.body && req.body.password)) return res.status(400).json({ error: 'a senha precisa ter de 10 a 128 caracteres' });
  setPass.run(hashPassword(req.body.password), req.params.username);
  logAudit(req.user.username, 'Senha redefinida', req.params.username);
  res.json({ ok: true });
});

router.post('/:username/unlock', (req, res) => {
  if (!find.get(req.params.username)) return res.status(404).json({ error: 'usuário não encontrado' });
  unlock.run(req.params.username);
  logAudit(req.user.username, 'Conta desbloqueada', req.params.username);
  res.json({ ok: true });
});

router.delete('/:username', (req, res) => {
  const u = find.get(req.params.username);
  if (!u) return res.status(404).json({ error: 'usuário não encontrado' });
  if (u.username === req.user.username) return res.status(400).json({ error: 'você não pode remover a própria conta' });
  if (u.role === 'admin' && admins.get().n <= 1) return res.status(400).json({ error: 'precisa sobrar pelo menos um administrador' });
  remove.run(u.username);
  logAudit(req.user.username, 'Usuário removido', u.username);
  res.status(204).end();
});

module.exports = router;
