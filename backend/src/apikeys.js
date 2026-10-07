const crypto = require('crypto');
const db = require('./db');

const hash = (key) => crypto.createHash('sha256').update(key).digest('hex');
const insert = db.prepare('INSERT INTO api_keys (name, key_hash, prefix, created_at) VALUES (?, ?, ?, ?)');
const find = db.prepare('SELECT id, last_used FROM api_keys WHERE key_hash = ? AND revoked = 0');
const touch = db.prepare('UPDATE api_keys SET last_used = ? WHERE id = ?');
const revokeStmt = db.prepare('UPDATE api_keys SET revoked = 1 WHERE id = ? AND revoked = 0');
const listStmt = db.prepare('SELECT id, name, prefix, created_at, last_used, revoked FROM api_keys ORDER BY id DESC');

// Cria uma chave por fonte de logs. O texto completo só existe aqui: no banco fica apenas o hash.
function create(name) {
  const key = 'soc_' + crypto.randomBytes(24).toString('base64url');
  const info = insert.run(name, hash(key), key.slice(0, 8), Date.now());
  return { id: Number(info.lastInsertRowid), name, key, prefix: key.slice(0, 8) };
}

function verifyKey(key) {
  const row = find.get(hash(String(key)));
  if (!row) return false;
  if (!row.last_used || Date.now() - row.last_used > 60_000) touch.run(Date.now(), row.id);
  return true;
}

const revoke = (id) => revokeStmt.run(id).changes > 0;
const list = () => listStmt.all().map((k) => ({ ...k, revoked: !!k.revoked }));

module.exports = { create, verifyKey, revoke, list };
