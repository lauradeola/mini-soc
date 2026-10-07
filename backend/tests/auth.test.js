process.env.DB_PATH = ':memory:';
process.env.JWT_SECRET = 'segredo-so-para-testes';
const test = require('node:test');
const assert = require('node:assert/strict');
const db = require('../src/db');
const { hashPassword, verifyPassword, signToken, readToken, authenticate } = require('../src/auth');

test('senha correta passa e senha errada não', () => {
  const h = hashPassword('uma-senha-forte');
  assert.equal(verifyPassword('uma-senha-forte', h), true);
  assert.equal(verifyPassword('outra', h), false);
});

test('o mesmo texto gera hashes diferentes (sal único)', () => {
  assert.notEqual(hashPassword('x'), hashPassword('x'));
});

test('token válido volta com usuário, perfil e versão da sessão', () => {
  const t = signToken({ username: 'admin', role: 'admin' });
  assert.deepEqual(readToken(t), { username: 'admin', role: 'admin', tv: 0 });
});

test('token adulterado é recusado', () => {
  const t = signToken({ username: 'analista', role: 'analyst' });
  const [h, , s] = t.split('.');
  const forged = Buffer.from(JSON.stringify({ sub: 'analista', role: 'admin' })).toString('base64url');
  assert.equal(readToken(`${h}.${forged}.${s}`), null);
  assert.equal(readToken('lixo'), null);
});

test('encerrar sessões e remover usuário derrubam os tokens', () => {
  db.prepare('INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)').run('lia', hashPassword('x'), 'analyst', Date.now());
  const t = signToken({ username: 'lia', role: 'analyst', token_version: 0 });
  assert.equal(authenticate(t).username, 'lia');
  db.prepare('UPDATE users SET token_version = token_version + 1 WHERE username = ?').run('lia');
  assert.equal(authenticate(t), null);
  const t2 = signToken({ username: 'lia', role: 'analyst', token_version: 1 });
  assert.equal(authenticate(t2).username, 'lia');
  db.prepare('DELETE FROM users WHERE username = ?').run('lia');
  assert.equal(authenticate(t2), null);
});
