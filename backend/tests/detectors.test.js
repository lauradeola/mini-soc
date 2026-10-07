process.env.DB_PATH = ':memory:';
const test = require('node:test');
const assert = require('node:assert/strict');
const db = require('../src/db');
const { ingest } = require('../src/ingest');

const login = (ip, username, success = false) => ingest({ ip, type: 'login', username, success });
const alertsFor = (ip) => db.prepare('SELECT * FROM alerts WHERE ip = ?').all(ip);

test('força bruta dispara no limite e respeita o cooldown', () => {
  const ip = '203.0.113.9';
  for (let i = 0; i < 4; i++) assert.equal(login(ip, 'admin').alerts.length, 0);
  const r = login(ip, 'admin');
  assert.equal(r.alerts.length, 1);
  assert.equal(r.alerts[0].type, 'brute_force');
  assert.equal(r.alerts[0].severity, 'medium');
  for (let i = 0; i < 5; i++) login(ip, 'admin');
  assert.equal(alertsFor(ip).length, 1);
});

test('credential stuffing vence a força bruta para o mesmo IP', () => {
  const ip = '203.0.113.10';
  ['ana', 'carlos', 'marina'].forEach((u) => assert.equal(login(ip, u).alerts.length, 0));
  assert.equal(login(ip, 'joao').alerts[0].type, 'cred_stuffing');
  login(ip, 'ana'); // 5ª falha: a força bruta dispararia aqui
  assert.deepEqual(alertsFor(ip).map((a) => a.type), ['cred_stuffing']);
});

test('varredura de portas dispara com portas diferentes', () => {
  const ip = '198.51.100.7';
  let alert = null;
  for (let p = 1; p <= 8; p++) {
    const r = ingest({ ip, type: 'port_access', port: 1000 + p });
    if (r.alerts.length) alert = r.alerts[0];
  }
  assert.equal(alert.type, 'port_scan');
  assert.equal(alert.count, 8);
});

test('a mesma porta repetida não é varredura', () => {
  const ip = '198.51.100.8';
  for (let i = 0; i < 20; i++) ingest({ ip, type: 'port_access', port: 443 });
  assert.equal(alertsFor(ip).length, 0);
});

test('logins bem-sucedidos não geram alertas', () => {
  const ip = '192.0.2.77';
  for (let i = 0; i < 20; i++) login(ip, 'ana', true);
  assert.equal(alertsFor(ip).length, 0);
});

test('IP bloqueado é descartado', () => {
  const ip = '192.0.2.5';
  db.prepare('INSERT INTO blocks (ip, ts, reason) VALUES (?, ?, ?)').run(ip, Date.now(), 'teste');
  const r = login(ip, 'admin');
  assert.equal(r.dropped, true);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM events WHERE ip = ?').get(ip).n, 0);
});
