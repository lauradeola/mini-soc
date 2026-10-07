#!/usr/bin/env node
// Coletor de logs: acompanha um arquivo (por padrão o auth.log do SSH) e envia cada
// tentativa de login para a API do Mini SOC.
//
// Uso:   API_KEY=sua-chave node tail-log.js [arquivo] [--replay]
//   --replay   lê o arquivo desde o começo (útil para testar com samples/auth.log)
// Env:   API_URL (padrão http://localhost:3000), API_KEY, LOG_FILE
const fs = require('fs');
const { parseLine } = require('./parser');

const args = process.argv.slice(2);
const FILE = args.find((a) => !a.startsWith('--')) || process.env.LOG_FILE || '/var/log/auth.log';
const API_URL = (process.env.API_URL || 'http://localhost:3000').replace(/\/$/, '');
const API_KEY = process.env.API_KEY || '';
const REPLAY = args.includes('--replay');

if (!API_KEY) console.warn('Aviso: API_KEY não definida. O servidor vai recusar os eventos.');

const queue = [];
let busy = false;
let sent = 0;

async function send(ev) {
  try {
    const r = await fetch(`${API_URL}/api/logs`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': API_KEY },
      body: JSON.stringify(ev),
      signal: AbortSignal.timeout(5000),
    });
    if (r.status === 401) console.error('O servidor recusou a API_KEY.');
    else if (r.ok || r.status === 202) sent++;
  } catch (e) {
    console.error('Falha ao enviar evento:', e.message);
  }
}

async function drain() {
  if (busy) return;
  busy = true;
  while (queue.length) await send(queue.shift());
  busy = false;
}

let pos = REPLAY || !fs.existsSync(FILE) ? 0 : fs.statSync(FILE).size;
let rest = '';

function readNew() {
  let st;
  try { st = fs.statSync(FILE); } catch (_) { return; }
  if (st.size < pos) pos = 0; // o arquivo foi rotacionado
  if (st.size === pos) return;
  const fd = fs.openSync(FILE, 'r');
  const buf = Buffer.alloc(st.size - pos);
  fs.readSync(fd, buf, 0, buf.length, pos);
  fs.closeSync(fd);
  pos = st.size;
  const lines = (rest + buf.toString('utf8')).split('\n');
  rest = lines.pop();
  for (const line of lines) {
    const ev = parseLine(line);
    if (ev) queue.push(ev);
  }
  drain();
}

console.log(`Lendo ${FILE} e enviando para ${API_URL}${REPLAY ? ' (do começo)' : ''}`);
readNew();
setInterval(readNew, 1000);
setInterval(() => { if (sent) { console.log(`${sent} eventos enviados`); sent = 0; } }, 10000);
