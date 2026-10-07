require('dotenv').config();
const http = require('http');
const db = require('./db');
const log = require('./logger');
const { seedUsers } = require('./auth');
const { attachWs } = require('./ws');
const { sweep } = require('./response');
const { backupNow } = require('./backup');
const { createApp, ORIGINS } = require('./app');

const PORT = process.env.PORT || 3000;
const RETENTION_DAYS = Math.max(7, Number(process.env.RETENTION_DAYS) || 90);

seedUsers();

const server = http.createServer(createApp());
const wss = attachWs(server, ORIGINS);

if (process.env.SIMULATE === 'true') require('./simulator').start();

// Limpeza periódica: eventos de 24 h, alertas e auditoria conforme RETENTION_DAYS; libera bloqueios vencidos
const pruneEvents = db.prepare(`DELETE FROM events WHERE ts < ?`);
const pruneHistory = db.prepare(`DELETE FROM alert_history WHERE alert_id IN (SELECT id FROM alerts WHERE ts < ?)`);
const pruneAlerts = db.prepare(`DELETE FROM alerts WHERE ts < ?`);
const pruneAudit = db.prepare(`DELETE FROM audit WHERE ts < ?`);
const timers = [
  setInterval(() => pruneEvents.run(Date.now() - 86_400_000), 600_000),
  setInterval(() => {
    const cut = Date.now() - RETENTION_DAYS * 86_400_000;
    pruneHistory.run(cut); pruneAlerts.run(cut); pruneAudit.run(cut);
  }, 3_600_000),
  setInterval(sweep, 30_000),
];

// Backup diário opcional (BACKUP_DIR), guardando as últimas 7 cópias
if (process.env.BACKUP_DIR && process.env.DB_PATH !== ':memory:') {
  const run = () => backupNow(process.env.BACKUP_DIR)
    .then((file) => log.info('backup concluído', { file }))
    .catch((e) => log.error('backup falhou', { error: e.message }));
  timers.push(setInterval(run, 86_400_000));
  setTimeout(run, 60_000).unref();
}

// Encerramento limpo: fecha conexões, para os timers e fecha o banco
function shutdown(signal) {
  log.info('encerrando', { signal });
  timers.forEach(clearInterval);
  wss.clients.forEach((c) => c.terminate());
  server.close(() => { try { db.close(); } catch (_) { /* já fechado */ } process.exit(0); });
  setTimeout(() => process.exit(1), 5000).unref();
}
['SIGINT', 'SIGTERM'].forEach((s) => process.on(s, () => shutdown(s)));

server.listen(PORT, () => log.info('servidor no ar', { url: `http://localhost:${PORT}`, websocket: '/ws', simulacao: process.env.SIMULATE === 'true' }));
