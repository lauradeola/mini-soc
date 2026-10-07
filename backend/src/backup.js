const fs = require('fs');
const path = require('path');
const db = require('./db');

const KEEP = 7;

// Copia o banco com segurança (mesmo em uso) e mantém só as últimas 7 cópias
async function backupNow(dir) {
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `soc-${new Date().toISOString().slice(0, 10)}.db`);
  await db.backup(file);
  const files = fs.readdirSync(dir).filter((f) => /^soc-\d{4}-\d{2}-\d{2}\.db$/.test(f)).sort();
  while (files.length > KEEP) fs.unlinkSync(path.join(dir, files.shift()));
  return file;
}

module.exports = { backupNow };
