const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { requireAuth } = require('./auth');
const { verifyKey } = require('./apikeys');
const metrics = require('./metrics');
const log = require('./logger');

const ORIGINS = (process.env.FRONTEND_ORIGIN || 'http://localhost:5500,http://127.0.0.1:5500')
  .split(',').map((s) => s.trim());

// Quem envia logs apresenta a chave do .env (API_KEY) ou uma chave criada por fonte na tela Fontes
function requireApiKey(req, res, next) {
  const given = Buffer.from(req.get('x-api-key') || '');
  const expected = Buffer.from(process.env.API_KEY || '');
  if (expected.length && given.length === expected.length && crypto.timingSafeEqual(given, expected)) return next();
  if (given.length && verifyKey(given.toString())) return next();
  res.status(401).json({ error: 'não autorizado' });
}

// Monta a aplicação sem ligar o servidor (assim os testes de API usam a mesma app)
function createApp() {
  const app = express();
  app.disable('x-powered-by');
  // "upgrade-insecure-requests" desligado: ele quebra o acesso http://localhost no Safari
  app.use(helmet({
    contentSecurityPolicy: {
      directives: { ...helmet.contentSecurityPolicy.getDefaultDirectives(), 'upgrade-insecure-requests': null },
    },
  }));
  app.use(cors({ origin: ORIGINS }));
  app.use(express.json({ limit: '10kb' }));

  app.use((req, res, next) => {
    const t = process.hrtime.bigint();
    res.on('finish', () => {
      if (req.path === '/api/health') return;
      log.info('http', { method: req.method, path: req.path, status: res.statusCode, ms: Number((process.hrtime.bigint() - t) / 1000000n) });
    });
    next();
  });

  app.get('/api/health', (_req, res) => res.json({ status: 'ok' }));
  app.get('/metrics', metrics.handler);
  app.use('/api/logs', requireApiKey, require('./routes/logs'));

  app.use('/api', rateLimit({ windowMs: 60_000, limit: 600, standardHeaders: true, legacyHeaders: false }));
  app.use('/api/auth', require('./routes/auth'));
  app.use('/api/alerts', requireAuth, require('./routes/alerts'));
  app.use('/api/blocks', requireAuth, require('./routes/blocks'));
  app.use('/api/rules', requireAuth, require('./routes/rules'));
  app.use('/api/audit', requireAuth, require('./routes/audit'));
  app.use('/api/simulate', requireAuth, require('./routes/simulate'));
  app.use('/api/ips', requireAuth, require('./routes/ips'));
  app.use('/api/users', requireAuth, require('./routes/users'));
  app.use('/api/settings', requireAuth, require('./routes/settings'));
  app.use('/api/keys', requireAuth, require('./routes/keys'));

  // Entrega o painel quando a pasta frontend existe (Docker ou execução na raiz do projeto)
  const front = path.join(__dirname, '..', '..', 'frontend');
  if (fs.existsSync(front)) app.use(express.static(front));

  app.use((err, _req, res, _next) => {
    if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'JSON inválido' });
    log.error('erro não tratado', { error: err.message });
    res.status(500).json({ error: 'erro interno' });
  });
  return app;
}

module.exports = { createApp, ORIGINS };
