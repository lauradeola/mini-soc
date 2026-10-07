const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const db = require('./db');

const SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
if (!process.env.JWT_SECRET && process.env.LOG_LEVEL !== 'silent') {
  console.warn('JWT_SECRET não definido: usando uma chave temporária (os logins caem ao reiniciar).');
}

// Senhas com scrypt (nativo do Node), com sal único por usuário
function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(password, salt, 64);
  return `${salt.toString('hex')}:${key.toString('hex')}`;
}

function verifyPassword(password, stored) {
  const [salt, key] = String(stored).split(':');
  if (!salt || !key) return false;
  const derived = crypto.scryptSync(password, Buffer.from(salt, 'hex'), 64);
  const expected = Buffer.from(key, 'hex');
  return derived.length === expected.length && crypto.timingSafeEqual(derived, expected);
}

// O token carrega a "versão" da sessão do usuário: trocar a senha ou "encerrar todas as sessões" derruba os tokens antigos
const signToken = (user) =>
  jwt.sign({ sub: user.username, role: user.role, tv: user.token_version || 0 }, SECRET, { expiresIn: '8h' });

function readToken(token) {
  try {
    const p = jwt.verify(token, SECRET, { algorithms: ['HS256'] });
    return { username: p.sub, role: p.role, tv: p.tv || 0 };
  } catch (_) {
    return null;
  }
}

const lookup = db.prepare('SELECT role, token_version FROM users WHERE username = ?');

// Confere o token e também se o usuário ainda existe, com o mesmo perfil e a mesma versão de sessão
function authenticate(token) {
  const t = readToken(token);
  if (!t) return null;
  const row = lookup.get(t.username);
  if (!row || (row.token_version || 0) !== t.tv) return null;
  return { username: t.username, role: row.role, token_version: row.token_version || 0 };
}

function requireAuth(req, res, next) {
  const h = req.get('authorization') || '';
  const user = h.startsWith('Bearer ') ? authenticate(h.slice(7)) : null;
  if (!user) return res.status(401).json({ error: 'não autenticado' });
  req.user = user;
  next();
}

const requireRole = (role) => (req, res, next) =>
  req.user && req.user.role === role ? next() : res.status(403).json({ error: 'sem permissão' });

// Cria o administrador e o analista na primeira execução
function seedUsers() {
  if (db.prepare('SELECT COUNT(*) AS n FROM users').get().n > 0) return;
  const insert = db.prepare('INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)');
  const make = (username, role, envName) => {
    let password = process.env[envName];
    const generated = !password;
    if (generated) password = crypto.randomBytes(9).toString('base64url');
    insert.run(username, hashPassword(password), role, Date.now());
    if (generated) console.log(`Usuário "${username}" (${role}) criado. Senha gerada, anote agora: ${password}`);
  };
  make('admin', 'admin', 'ADMIN_PASSWORD');
  make('analista', 'analyst', 'ANALYST_PASSWORD');
}

module.exports = { hashPassword, verifyPassword, signToken, readToken, authenticate, requireAuth, requireRole, seedUsers };
