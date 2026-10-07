const test = require('node:test');
const assert = require('node:assert/strict');
const { parseLine } = require('./parser');

test('falha de senha com usuário inexistente', () => {
  const ev = parseLine('Oct  3 10:10:01 srv sshd[1]: Failed password for invalid user admin from 203.0.113.99 port 40000 ssh2');
  assert.deepEqual(ev, { ip: '203.0.113.99', type: 'login', username: 'admin', success: false });
});

test('falha de senha com usuário existente', () => {
  const ev = parseLine('Oct  3 10:10:01 srv sshd[1]: Failed password for root from 198.51.100.7 port 41000 ssh2');
  assert.deepEqual(ev, { ip: '198.51.100.7', type: 'login', username: 'root', success: false });
});

test('login aceito por senha e por chave', () => {
  assert.equal(parseLine('x sshd[1]: Accepted password for ana from 192.0.2.10 port 50 ssh2').success, true);
  assert.equal(parseLine('x sshd[1]: Accepted publickey for ana from 192.0.2.10 port 50 ssh2').username, 'ana');
});

test('linhas que não são login são ignoradas', () => {
  assert.equal(parseLine('x sshd[1]: Invalid user admin from 203.0.113.99 port 40000'), null);
  assert.equal(parseLine('x sshd[1]: pam_unix(sshd:session): session opened for user ana'), null);
  assert.equal(parseLine(''), null);
});
