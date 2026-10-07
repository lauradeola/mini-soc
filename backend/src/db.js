const Database = require('better-sqlite3');
const path = require('path');

const file = process.env.DB_PATH || path.join(__dirname, '..', 'soc.db');
const db = new Database(file);
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS events (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       INTEGER NOT NULL,
    ip       TEXT    NOT NULL,
    type     TEXT    NOT NULL,
    username TEXT,
    success  INTEGER NOT NULL DEFAULT 0,
    port     INTEGER
  );
  CREATE INDEX IF NOT EXISTS idx_events_ip_ts ON events (ip, ts);

  CREATE TABLE IF NOT EXISTS alerts (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       INTEGER NOT NULL,
    type     TEXT    NOT NULL,
    severity TEXT    NOT NULL,
    ip       TEXT    NOT NULL,
    message  TEXT    NOT NULL,
    count    INTEGER NOT NULL,
    status   TEXT    NOT NULL DEFAULT 'open'
  );
  CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts (ts DESC);

  CREATE TABLE IF NOT EXISTS alert_history (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER NOT NULL,
    ts       INTEGER NOT NULL,
    username TEXT    NOT NULL,
    text     TEXT    NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_hist_alert ON alert_history (alert_id);

  CREATE TABLE IF NOT EXISTS blocks (
    ip         TEXT PRIMARY KEY,
    ts         INTEGER NOT NULL,
    reason     TEXT NOT NULL DEFAULT '',
    expires_at INTEGER,
    blocked_by TEXT NOT NULL DEFAULT ''
  );

  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('admin', 'analyst')),
    created_at    INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS audit (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       INTEGER NOT NULL,
    username TEXT NOT NULL,
    action   TEXT NOT NULL,
    detail   TEXT NOT NULL DEFAULT ''
  );
  CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit (ts DESC);

  CREATE TABLE IF NOT EXISTS config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS api_keys (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    key_hash   TEXT NOT NULL UNIQUE,
    prefix     TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_used  INTEGER,
    revoked    INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS user_ips (
    username   TEXT NOT NULL,
    ip         TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    PRIMARY KEY (username, ip)
  );
`);

// Bancos criados em versões anteriores ganham as colunas novas
for (const sql of [
  `ALTER TABLE alerts ADD COLUMN status TEXT NOT NULL DEFAULT 'open'`,
  `ALTER TABLE blocks ADD COLUMN expires_at INTEGER`,
  `ALTER TABLE blocks ADD COLUMN blocked_by TEXT NOT NULL DEFAULT ''`,
  `ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE users ADD COLUMN failed_logins INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE users ADD COLUMN locked_until INTEGER`,
]) {
  try { db.exec(sql); } catch (_) { /* a coluna já existe */ }
}

module.exports = db;
