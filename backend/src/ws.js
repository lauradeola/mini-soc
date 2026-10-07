const { WebSocketServer } = require('ws');
const bus = require('./bus');
const { authenticate } = require('./auth');
const metrics = require('./metrics');

// Transmite eventos, alertas e bloqueios aos painéis conectados.
// Só entra quem apresenta um token válido (usuário ativo, sessão não encerrada) e vem de uma origem permitida.
function attachWs(server, allowedOrigins) {
  const wss = new WebSocketServer({
    server,
    path: '/ws',
    verifyClient: ({ origin, req }) => {
      const token = new URL(req.url, 'http://localhost').searchParams.get('token');
      if (!token || !authenticate(token)) return false;
      if (!origin) return true;
      try {
        return allowedOrigins.includes(origin) || new URL(origin).host === req.headers.host;
      } catch (_) {
        return false;
      }
    },
  });

  // Batimento: derruba conexões que não respondem ao ping
  wss.on('connection', (ws) => {
    ws.isAlive = true;
    ws.on('pong', () => { ws.isAlive = true; });
  });
  const beat = setInterval(() => {
    wss.clients.forEach((c) => {
      if (!c.isAlive) return c.terminate();
      c.isAlive = false;
      c.ping();
    });
  }, 30_000);
  beat.unref();
  wss.on('close', () => clearInterval(beat));

  const send = (kind, data) => {
    const msg = JSON.stringify({ kind, data });
    wss.clients.forEach((c) => c.readyState === 1 && c.send(msg));
  };
  ['event', 'alert', 'alert_update', 'block', 'unblock'].forEach((k) => bus.on(k, (d) => send(k, d)));
  metrics.setWsCounter(() => wss.clients.size);
  return wss;
}

module.exports = { attachWs };
