process.env.DB_PATH = ':memory:';
const test = require('node:test');
const assert = require('node:assert/strict');
const db = require('../src/db');
const rules = require('../src/rules');
const { load, save } = require('../src/config');
const keys = require('../src/apikeys');
const { ingest } = require('../src/ingest');
const { checkOffHours } = require('../src/detectors/offHours');

const ok = (ip, username) => ingest({ ip, type: 'login', username, success: true });

test('configuração salva volta igual e completa campos novos com os padrões', () => {
  save('teste', { a: { x: 9 } });
  assert.deepEqual(load('teste', { a: { x: 1, y: 2 } }), { a: { x: 9, y: 2 } });
  assert.deepEqual(load('inexistente', { b: { z: 1 } }), { b: { z: 1 } });
});

test('chave de API por fonte: funciona, não guarda o texto e deixa de funcionar ao revogar', () => {
  const k = keys.create('servidor-web');
  assert.ok(k.key.startsWith('soc_'));
  assert.equal(keys.verifyKey(k.key), true);
  assert.equal(keys.verifyKey('soc_errada'), false);
  const stored = db.prepare('SELECT key_hash FROM api_keys WHERE id = ?').get(k.id).key_hash;
  assert.notEqual(stored, k.key);
  assert.equal(keys.revoke(k.id), true);
  assert.equal(keys.verifyKey(k.key), false);
  assert.equal(keys.list().find((x) => x.id === k.id).revoked, true);
});

test('login de IP novo só alerta quando a conta já tem histórico', () => {
  rules.new_ip.on = true; rules.new_ip.limit = 2;
  assert.equal(ok('203.0.113.60', 'ana').alerts.length, 0);   // 1º IP: sem histórico
  assert.equal(ok('203.0.113.61', 'ana').alerts.length, 0);   // 2º IP: ainda sem histórico suficiente
  const r = ok('203.0.113.62', 'ana');                        // 3º IP: a conta já usou 2
  assert.equal(r.alerts.length, 1);
  assert.equal(r.alerts[0].type, 'new_ip');
  assert.equal(ok('203.0.113.62', 'ana').alerts.length, 0);   // mesmo IP de novo: conhecido
});

test('login fora do horário só alerta quando a regra está ligada', () => {
  process.env.WORK_HOURS = '07-20';
  const at = (h) => ({ ts: new Date(2026, 0, 5, h, 0).getTime(), ip: '192.0.2.70', type: 'login', username: 'ana', success: true });
  rules.off_hours.on = false;
  assert.equal(checkOffHours(at(3)), null);
  rules.off_hours.on = true;
  assert.equal(checkOffHours(at(10)), null);
  assert.equal(checkOffHours(at(3)).type, 'off_hours');
  rules.off_hours.on = false;
});
