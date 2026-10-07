process.env.DB_PATH = ':memory:';
process.env.ALLOWLIST = '192.0.2.50';
const test = require('node:test');
const assert = require('node:assert/strict');
const db = require('../src/db');
const settings = require('../src/settings');
const { ingest } = require('../src/ingest');
const { blockIp, sweep } = require('../src/response');

const login = (ip, username, success = false) => ingest({ ip, type: 'login', username, success });
const blocked = (ip) => db.prepare('SELECT * FROM blocks WHERE ip = ?').get(ip);

test('acesso bem-sucedido após falhas gera alerta crítico de comprometimento', () => {
  const ip = '203.0.113.21';
  for (let i = 0; i < 4; i++) login(ip, 'carlos');
  const r = login(ip, 'carlos', true);
  assert.equal(r.alerts.length, 1);
  assert.equal(r.alerts[0].type, 'compromise');
  assert.equal(r.alerts[0].severity, 'critical');
});

test('sem falhas antes, o login normal não gera alerta', () => {
  const ip = '203.0.113.22';
  assert.equal(login(ip, 'ana', true).alerts.length, 0);
});

test('bloqueio automático só acontece quando está ligado', () => {
  const off = '203.0.113.23', on = '203.0.113.24';
  settings.autoBlock.on = false;
  for (let i = 0; i < 4; i++) login(off, 'deploy');
  login(off, 'deploy', true);
  assert.equal(blocked(off), undefined);

  settings.autoBlock.on = true; settings.autoBlock.minutes = 30;
  for (let i = 0; i < 4; i++) login(on, 'deploy');
  login(on, 'deploy', true);
  const b = blocked(on);
  assert.ok(b);
  assert.ok(b.expires_at > Date.now());
  assert.equal(b.blocked_by, 'sistema');
  settings.autoBlock.on = false;
});

test('IP da ALLOWLIST nunca é bloqueado', () => {
  assert.equal(blockIp('192.0.2.50', 'manual', { by: 'admin' }), null);
  assert.equal(blocked('192.0.2.50'), undefined);
});

test('bloqueio com prazo é liberado pelo sweep', () => {
  const ip = '192.0.2.51';
  blockIp(ip, 'manual', { minutes: 5, by: 'admin' });
  assert.ok(blocked(ip));
  db.prepare('UPDATE blocks SET expires_at = ? WHERE ip = ?').run(Date.now() - 1, ip);
  sweep();
  assert.equal(blocked(ip), undefined);
});
