const net = require('net');
const { load } = require('./config');

// Resposta automática (salva no banco): bloqueia sozinho os alertas críticos, por alguns minutos
const settings = load('settings', { autoBlock: { on: false, minutes: 60 } });

// IPs que nunca podem ser bloqueados: variável ALLOWLIST do .env, separados por vírgula
settings.allowlist = () =>
  (process.env.ALLOWLIST || '').split(',').map((s) => s.trim()).filter((s) => net.isIP(s));

module.exports = settings;
