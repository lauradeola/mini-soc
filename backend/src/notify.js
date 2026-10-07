const NAMES = { brute_force: 'Força bruta', cred_stuffing: 'Credential stuffing', compromise: 'Acesso após falhas', new_ip: 'Login de novo IP', off_hours: 'Login fora do horário', port_scan: 'Varredura de portas' };
const SEV = { medium: 'média', high: 'alta', critical: 'crítica' };

const telegram = () => process.env.TELEGRAM_BOT_TOKEN && process.env.TELEGRAM_CHAT_ID;
const configured = () => Boolean(process.env.WEBHOOK_URL || telegram());

const post = (url, body) => fetch(url, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
  signal: AbortSignal.timeout(5000),
});

// Avisa por webhook (formato do Slack) e/ou Telegram quando o alerta é alto ou crítico
async function notifyAlert(alert) {
  if (alert.severity !== 'high' && alert.severity !== 'critical') return;
  const text = `[Mini SOC] Alerta ${SEV[alert.severity]}: ${NAMES[alert.type]} em ${alert.ip}. ${alert.message}`;
  const jobs = [];
  if (process.env.WEBHOOK_URL) jobs.push(post(process.env.WEBHOOK_URL, { text }));
  if (telegram()) {
    jobs.push(post(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
      chat_id: process.env.TELEGRAM_CHAT_ID, text,
    }));
  }
  await Promise.allSettled(jobs);
}

module.exports = { notifyAlert, configured };
