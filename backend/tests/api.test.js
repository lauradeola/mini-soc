process.env.DB_PATH = ':memory:';
process.env.JWT_SECRET = 'segredo-so-para-testes';
process.env.ADMIN_PASSWORD = 'senha-admin-123';
process.env.ANALYST_PASSWORD = 'senha-analista-123';
process.env.API_KEY = 'chave-de-teste';
process.env.ALLOWLIST = '192.0.2.250';
process.env.LOG_LEVEL = 'silent';
process.env.LOGIN_RATE_LIMIT = '1000';
delete process.env.METRICS_TOKEN;

const test = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const db = require('../src/db');
const { seedUsers } = require('../src/auth');
const { createApp } = require('../src/app');

seedUsers();
const app = createApp();
const ADMIN = 'senha-admin-123', ANALYST = 'senha-analista-123';

const login = (username, password) => request(app).post('/api/auth/login').send({ username, password });
const tokenOf = async (u, p) => (await login(u, p)).body.token;
const bearer = (t) => ({ Authorization: `Bearer ${t}` });
const sendLog = (key, body) => request(app).post('/api/logs').set('x-api-key', key).send(body);

test('login correto devolve token e perfil', async () => {
  const r = await login('admin', ADMIN);
  assert.equal(r.status, 200);
  assert.equal(r.body.user.role, 'admin');
  assert.ok(r.body.token);
});

test('senha errada e usuário inexistente recebem a mesma resposta', async () => {
  const a = await login('admin', 'errada');
  const b = await login('naoexiste', 'errada');
  assert.equal(a.status, 401);
  assert.equal(b.status, 401);
  assert.deepEqual(a.body, b.body);
});

test('rotas protegidas exigem token', async () => {
  assert.equal((await request(app).get('/api/alerts')).status, 401);
  assert.equal((await request(app).get('/api/alerts').set(bearer('lixo'))).status, 401);
});

test('analista não bloqueia IP; administrador bloqueia e desbloqueia', async () => {
  const analyst = await tokenOf('analista', ANALYST), admin = await tokenOf('admin', ADMIN);
  const body = { ip: '203.0.113.9', reason: 'manual' };
  assert.equal((await request(app).post('/api/blocks').set(bearer(analyst)).send(body)).status, 403);
  assert.equal((await request(app).post('/api/blocks').set(bearer(admin)).send(body)).status, 201);
  const list = await request(app).get('/api/blocks').set(bearer(analyst));
  assert.ok(list.body.some((b) => b.ip === '203.0.113.9'));
  assert.equal((await request(app).delete('/api/blocks/203.0.113.9').set(bearer(admin))).status, 204);
});

test('IP da ALLOWLIST não pode ser bloqueado', async () => {
  const admin = await tokenOf('admin', ADMIN);
  const r = await request(app).post('/api/blocks').set(bearer(admin)).send({ ip: '192.0.2.250', reason: 'manual' });
  assert.equal(r.status, 409);
});

test('a conta é travada após 5 senhas erradas e o administrador destrava', async () => {
  const admin = await tokenOf('admin', ADMIN);
  const created = await request(app).post('/api/users').set(bearer(admin)).send({ username: 'teste.trava', password: 'senha-longa-123', role: 'analyst' });
  assert.equal(created.status, 201);
  for (let i = 0; i < 5; i++) assert.equal((await login('teste.trava', 'errada')).status, 401);
  assert.equal((await login('teste.trava', 'senha-longa-123')).status, 429);
  assert.equal((await request(app).post('/api/users/teste.trava/unlock').set(bearer(admin))).status, 200);
  assert.equal((await login('teste.trava', 'senha-longa-123')).status, 200);
});

test('senha curta é recusada ao criar usuário', async () => {
  const admin = await tokenOf('admin', ADMIN);
  const r = await request(app).post('/api/users').set(bearer(admin)).send({ username: 'curto.demais', password: '123', role: 'analyst' });
  assert.equal(r.status, 400);
});

test('envio de logs exige chave de API', async () => {
  const ev = { ip: '198.51.100.99', type: 'login', username: 'ana', success: true };
  assert.equal((await request(app).post('/api/logs').send(ev)).status, 401);
  assert.equal((await sendLog('chave-errada', ev)).status, 401);
  assert.equal((await sendLog('chave-de-teste', ev)).status, 201);
});

test('chave por fonte funciona e deixa de funcionar ao ser revogada', async () => {
  const admin = await tokenOf('admin', ADMIN), analyst = await tokenOf('analista', ANALYST);
  assert.equal((await request(app).post('/api/keys').set(bearer(analyst)).send({ name: 'x1' })).status, 403);
  const created = await request(app).post('/api/keys').set(bearer(admin)).send({ name: 'servidor-web' });
  assert.equal(created.status, 201);
  const ev = { ip: '198.51.100.98', type: 'login', username: 'ana', success: true };
  assert.equal((await sendLog(created.body.key, ev)).status, 201);
  assert.equal((await request(app).delete(`/api/keys/${created.body.id}`).set(bearer(admin))).status, 204);
  assert.equal((await sendLog(created.body.key, ev)).status, 401);
});

test('encerrar todas as sessões derruba o token', async () => {
  const t = await tokenOf('analista', ANALYST);
  assert.equal((await request(app).get('/api/alerts').set(bearer(t))).status, 200);
  assert.equal((await request(app).post('/api/auth/logout-all').set(bearer(t))).status, 200);
  assert.equal((await request(app).get('/api/alerts').set(bearer(t))).status, 401);
});

test('o token renovado continua valendo', async () => {
  const t = await tokenOf('admin', ADMIN);
  const r = await request(app).post('/api/auth/refresh').set(bearer(t));
  assert.equal(r.status, 200);
  assert.equal((await request(app).get('/api/alerts').set(bearer(r.body.token))).status, 200);
});

test('ataque enviado pela API vira alerta com histórico', async () => {
  for (let i = 0; i < 5; i++) await sendLog('chave-de-teste', { ip: '198.51.100.200', type: 'login', username: 'root', success: false });
  const admin = await tokenOf('admin', ADMIN);
  const r = await request(app).get('/api/alerts').set(bearer(admin));
  const a = r.body.find((x) => x.ip === '198.51.100.200');
  assert.equal(a.type, 'brute_force');
  assert.ok(a.history.length >= 1);
});

test('fluxo de investigação: investigar, anotar e resolver', async () => {
  const admin = await tokenOf('admin', ADMIN);
  const id = (await request(app).get('/api/alerts').set(bearer(admin))).body[0].id;
  const patch = (b) => request(app).patch(`/api/alerts/${id}`).set(bearer(admin)).send(b);
  assert.equal((await patch({ action: 'investigate' })).body.status, 'investigating');
  assert.equal((await patch({ action: 'note', text: 'falei com o dono da conta' })).status, 200);
  assert.equal((await patch({ action: 'resolve' })).body.status, 'resolved');
  assert.equal((await patch({ action: 'apagar' })).status, 400);
});

test('regras alteradas pelo administrador ficam salvas no banco', async () => {
  const admin = await tokenOf('admin', ADMIN), analyst = await tokenOf('analista', ANALYST);
  assert.equal((await request(app).put('/api/rules').set(bearer(analyst)).send({ brute_force: { limit: 9 } })).status, 403);
  const r = await request(app).put('/api/rules').set(bearer(admin)).send({ brute_force: { limit: 7 } });
  assert.equal(r.status, 200);
  assert.equal(r.body.brute_force.limit, 7);
  assert.match(db.prepare("SELECT value FROM config WHERE key = 'rules'").get().value, /"limit":7/);
  await request(app).put('/api/rules').set(bearer(admin)).send({ brute_force: { limit: 5 } });
});

test('a auditoria só é lida pelo administrador e registra as ações', async () => {
  const admin = await tokenOf('admin', ADMIN), analyst = await tokenOf('analista', ANALYST);
  assert.equal((await request(app).get('/api/audit').set(bearer(analyst))).status, 403);
  const r = await request(app).get('/api/audit').set(bearer(admin));
  assert.equal(r.status, 200);
  assert.ok(r.body.some((x) => x.action === 'Login realizado'));
});

test('métricas ficam desligadas sem METRICS_TOKEN', async () => {
  assert.equal((await request(app).get('/metrics')).status, 404);
});
