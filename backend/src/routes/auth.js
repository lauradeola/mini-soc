const express = require('express');
const rateLimit = require('express-rate-limit');
const db = require('../db');
const { hashPassword, verifyPassword, signToken, requireAuth } = require('../auth');
const { logAudit } = require('../audit');

const router = express.Router();
const MAX_FAILS = 5;
const LOCK_MS = 15 * 60_000;

const find = db.prepare('SELECT username, password_hash, role, token_version, failed_logins, locked_until FROM users WHERE username = ?');
const countFail = db.prepare('UPDATE users SET failed_logins = ? WHERE username = ?');
const lock = db.prepare('UPDATE users SET failed_logins = 0, locked_until = ? WHERE username = ?');
const reset = db.prepare('UPDATE users SET failed_logins = 0, locked_until = NULL WHERE username = ?');
const setPassword = db.prepare('UPDATE users SET password_hash = ?, token_version = token_version + 1 WHERE username = ?');
const currentHash = db.prepare('SELECT password_hash FROM users WHERE username = ?');
const logoutAll = db.prepare('UPDATE users SET token_version = token_version + 1 WHERE username = ?');
const DUMMY = hashPassword('senha-falsa');

const limiter = rateLimit({
  windowMs: 60_000,
  limit: Number(process.env.LOGIN_RATE_LIMIT) || 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'muitas tentativas, aguarde um minuto' },
});

router.post('/login', limiter, (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string' || username.length > 64 || password.length > 128) {
    return res.status(400).json({ error: 'dados inválidos' });
  }
  const user = find.get(username);

  // Conta travada por excesso de tentativas: recusa mesmo com a senha certa
  if (user && user.locked_until && user.locked_until > Date.now()) {
    verifyPassword(password, DUMMY);
    logAudit(username, 'Login recusado: conta bloqueada temporariamente');
    return res.status(429).json({ error: 'conta bloqueada por excesso de tentativas, tente de novo em alguns minutos' });
  }

  // Faz a mesma conta mesmo quando o usuário não existe, para não revelar quais existem
  const ok = user ? verifyPassword(password, user.password_hash) : (verifyPassword(password, DUMMY), false);
  if (!ok) {
    logAudit(username, 'Falha de login');
    if (user) {
      const n = (user.failed_logins || 0) + 1;
      if (n >= MAX_FAILS) { lock.run(Date.now() + LOCK_MS, username); logAudit(username, 'Conta bloqueada após tentativas seguidas'); }
      else countFail.run(n, username);
    }
    return res.status(401).json({ error: 'usuário ou senha incorretos' });
  }
  reset.run(username);
  logAudit(user.username, 'Login realizado');
  res.json({ token: signToken(user), user: { username: user.username, role: user.role } });
});

router.get('/me', requireAuth, (req, res) => res.json({ username: req.user.username, role: req.user.role }));

// Renova o token enquanto a sessão continua válida
router.post('/refresh', requireAuth, (req, res) => res.json({ token: signToken(req.user) }));

// Derruba todos os tokens desta conta (outros navegadores e dispositivos também)
router.post('/logout-all', requireAuth, (req, res) => {
  logoutAll.run(req.user.username);
  logAudit(req.user.username, 'Todas as sessões encerradas');
  res.json({ ok: true });
});

router.post('/password', requireAuth, limiter, (req, res) => {
  const { current, next } = req.body || {};
  if (typeof current !== 'string' || typeof next !== 'string' || next.length < 10 || next.length > 128) {
    return res.status(400).json({ error: 'a nova senha precisa ter de 10 a 128 caracteres' });
  }
  if (!verifyPassword(current, currentHash.get(req.user.username).password_hash)) {
    return res.status(401).json({ error: 'senha atual incorreta' });
  }
  setPassword.run(hashPassword(next), req.user.username);
  logAudit(req.user.username, 'Senha alterada');
  res.json({ ok: true });
});

module.exports = router;
