const db = require('./db');

const get = db.prepare(`SELECT value FROM config WHERE key = ?`);
const put = db.prepare(`INSERT INTO config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`);

// Carrega uma configuração salva no banco, completando com os padrões do código (campos novos não se perdem)
function load(key, defaults) {
  const row = get.get(key);
  if (!row) return defaults;
  try {
    const saved = JSON.parse(row.value);
    for (const k of Object.keys(defaults)) {
      if (saved[k] && typeof saved[k] === 'object') Object.assign(defaults[k], saved[k]);
    }
  } catch (_) { /* valor corrompido: usa os padrões */ }
  return defaults;
}

const save = (key, obj) => put.run(key, JSON.stringify(obj));

module.exports = { load, save };
