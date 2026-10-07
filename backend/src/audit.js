const db = require('./db');

const insert = db.prepare('INSERT INTO audit (ts, username, action, detail) VALUES (?, ?, ?, ?)');

// Registra quem fez o quê, para consulta na tela de Auditoria
const logAudit = (username, action, detail = '') =>
  insert.run(Date.now(), String(username).slice(0, 64), action, String(detail).slice(0, 200));

module.exports = { logAudit };
