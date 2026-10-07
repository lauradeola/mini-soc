const { ingest } = require('./ingest');

const NETS = ['203.0.113.', '198.51.100.', '192.0.2.']; // faixas reservadas para documentação
const USERS = ['ana', 'carlos', 'marina', 'joao', 'deploy', 'suporte'];
const ATK = ['admin', 'root', 'test', 'oracle', 'ubuntu', 'postgres'];
const PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017];

const rnd = (a, b) => Math.floor(Math.random() * (b - a + 1)) + a;
const pick = (a) => a[rnd(0, a.length - 1)];
const rip = () => pick(NETS) + rnd(2, 250);
// Cada usuário entra sempre do mesmo IP, como numa rotina normal (evita alertas de "novo IP" falsos)
const HOME = Object.fromEntries(USERS.map((u, i) => [u, '198.51.100.' + (10 + i)]));

function background() {
  for (let i = rnd(1, 3); i > 0; i--) {
    const ip = rip(), r = Math.random();
    if (r < 0.8) { const u = pick(USERS); ingest({ ip: HOME[u], type: 'login', username: u, success: true }); }
    else if (r < 0.93) ingest({ ip, type: 'login', username: pick(USERS), success: false });
    else ingest({ ip, type: 'port_access', port: pick([22, 80, 443, 8080, 3306]) });
  }
}

// kind: 'brute' | 'stuff' | 'scan' | 'comp'. Para sozinho se o IP for bloqueado.
function burst(kind) {
  const ip = rip(), total = kind === 'comp' ? 6 : rnd(14, 24);
  let i = 0;
  const timer = setInterval(() => {
    if (i >= total) return clearInterval(timer);
    let r;
    if (kind === 'brute') r = ingest({ ip, type: 'login', username: pick(['admin', 'root']), success: false });
    else if (kind === 'stuff') r = ingest({ ip, type: 'login', username: pick(USERS.concat(ATK)), success: false });
    else if (kind === 'comp') r = ingest({ ip, type: 'login', username: 'deploy', success: i === 4 });
    else r = ingest({ ip, type: 'port_access', port: PORTS[i] || rnd(1, 65535) });
    if (r.dropped) return clearInterval(timer);
    i++;
  }, 220);
}

function start() {
  setInterval(background, 700);
  setInterval(() => burst(pick(['brute', 'stuff', 'scan', 'comp'])), 17_000);
  setTimeout(() => burst('brute'), 2500);
  console.log('Simulador de tráfego ligado (SIMULATE=true)');
}

module.exports = { start, burst };
