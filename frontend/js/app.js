const $ = s => document.querySelector(s), $$ = s => [...document.querySelectorAll(s)];
const rnd = (a, b) => Math.floor(Math.random() * (b - a + 1)) + a, pick = a => a[rnd(0, a.length - 1)];
const NETS = ['203.0.113.', '198.51.100.', '192.0.2.'], USERS = ['ana', 'carlos', 'marina', 'joao', 'deploy', 'suporte'], ATK = ['admin', 'root', 'test', 'oracle', 'ubuntu', 'postgres'];
const PORTS = [21,22,23,25,53,80,110,135,139,143,443,445,1433,3306,3389,5432,5900,6379,8080,8443,9200,27017];
const TI = { brute_force: 'Força bruta', cred_stuffing: 'Credential stuffing', compromise: 'Acesso após falhas', new_ip: 'Login de novo IP', off_hours: 'Login fora do horário', port_scan: 'Varredura de portas' }, SEV = { medium: 'Média', high: 'Alta', critical: 'Crítica' };
const RANK = { medium: 1, high: 2, critical: 3 }, VR = { medium: 'med', high: 'high', critical: 'crit' };
const TIPS = { new_ip: 'Confirme com o dono da conta. Se não foi ele, troque a senha, encerre as sessões e ative 2FA.', off_hours: 'Confirme se o acesso era esperado. Fora do expediente, vale checar o que foi feito na sessão.', compromise: 'Trate a conta como comprometida: force a troca de senha, encerre as sessões abertas e confira o que foi acessado depois do login.', cred_stuffing: 'Force a redefinição de senha das contas visadas, ative 2FA e verifique se há credenciais vazadas.', brute_force: 'Bloqueie o IP no firewall, exija 2FA nas contas visadas e limite as tentativas de login por minuto.', port_scan: 'Bloqueie o IP e confira se alguma das portas sondadas está exposta sem necessidade.' };
const RD = { new_ip: ['Login de novo IP', 'Avisa quando uma conta entra de um IP que nunca usou, depois de já ter histórico.', 'nowin'], off_hours: ['Login fora do horário', 'Avisa logins bem-sucedidos fora do horário de trabalho (variável WORK_HOURS do servidor, padrão 07-20).', 'none'], compromise: ['Acesso após falhas', 'Dispara quando um mesmo IP erra várias vezes e depois consegue entrar. É o sinal mais grave.'], cred_stuffing: ['Credential stuffing', 'Dispara quando um mesmo IP tenta usuários diferentes dentro da janela.'], brute_force: ['Força bruta', 'Dispara quando um mesmo IP acumula falhas de login dentro da janela.'], port_scan: ['Varredura de portas', 'Dispara quando um mesmo IP toca portas diferentes dentro da janela.'] };
const META = { overview: ['Visão geral', 'Resumo do tráfego e dos alertas'], alerts: ['Alertas', 'Tudo o que as regras detectaram'], events: ['Eventos', 'Registro bruto do tráfego em tempo real'], blocks: ['Bloqueios', 'IPs impedidos de acessar o ambiente'], rules: ['Regras de detecção', 'Defina quando um padrão vira alerta'], audit: ['Auditoria', 'Registro das ações feitas no painel'], users: ['Usuários', 'Quem pode acessar o painel'], incidents: ['Incidentes', 'Alertas do mesmo IP agrupados em uma só história'], keys: ['Fontes de logs', 'Uma chave por fonte, que pode ser revogada sozinha'] };
const MT = { new_ip: ['T1078', 'Valid Accounts', 'Initial Access'], off_hours: ['T1078', 'Valid Accounts', 'Initial Access'], compromise: ['T1078', 'Valid Accounts', 'Initial Access'], brute_force: ['T1110', 'Brute Force', 'Credential Access'], cred_stuffing: ['T1110.004', 'Credential Stuffing', 'Credential Access'], port_scan: ['T1046', 'Network Service Discovery', 'Discovery'] };
const S = { audit: [], notify: true, auto: { on: false, minutes: 15 }, cfg: null, ev: [], al: [], blk: new Map(), last: {}, paused: false, seq: 0, fresh: null, view: 'overview', f: { q: '', sev: 'all', st: 'all', per: 'all', n: 25 }, sort: { k: 'ts', d: -1 }, ef: 'all',
  rules: { brute_force: { on: true, limit: 5, win: 60 }, cred_stuffing: { on: true, limit: 4, win: 60 }, compromise: { on: true, limit: 3, win: 120 }, port_scan: { on: true, limit: 8, win: 30 } } };
let API = '', LIVE = false, TOKEN = '', ME = null, WSREF = null;
const can = () => !LIVE || (ME && ME.role === 'admin');
const hdr = () => ({ 'Content-Type': 'application/json', Authorization: 'Bearer ' + TOKEN });
const handle = r => { if (r.status === 401) { logout(); throw new Error('401'); } return r.status === 204 ? null : r.json(); };
const get = u => fetch(API + u, { headers: hdr() }).then(handle);
const post = (u, b, m = 'POST') => fetch(API + u, { method: m, headers: hdr(), body: b ? JSON.stringify(b) : undefined }).then(handle);
const patch = (id, action, text) => post('/api/alerts/' + id, { action, text }, 'PATCH').catch(() => {});
const rip = () => pick(NETS) + rnd(2, 250), hm = ts => new Date(ts).toLocaleTimeString('pt-BR');
const ago = ts => { const s = Math.max(0, Math.round((Date.now() - ts) / 1000)); return s < 60 ? 'há ' + s + 's' : 'há ' + Math.floor(s / 60) + ' min'; };
const lbl = x => x.t === 'port' ? 'Acesso à porta ' + x.port : x.ok ? 'Login de ' + esc(String(x.user)) : 'Falha de login (' + esc(String(x.user)) + ')';
const stOf = a => S.blk.has(a.ip) ? ['Bloqueado', 'b'] : a.res ? ['Resolvido', 'r'] : a.inv ? ['Em investigação', 'i'] : ['Aberto', 'o'];
const isOpen = a => !S.blk.has(a.ip) && !a.res;

const esc = t => t.replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const audit = t => { S.audit.unshift([Date.now(), t]); S.audit.length = Math.min(S.audit.length, 200); };
const act = (a, t) => { if (!a) return; a.hist.push([Date.now(), t]); audit(`${t} (${TI[a.type]}, ${a.ip})`); };
const risk = ip => { const w = { medium: 20, high: 35, critical: 50 }; let n = 0; S.al.forEach(a => { if (a.ip === ip) n += w[a.sev]; }); S.ev.forEach(x => { if (x.ip === ip && !(x.t === 'login' && x.ok)) n++; }); return Math.min(100, n); };
function toast(t) { const d = document.createElement('div'); d.textContent = t; $('#toast').append(d); setTimeout(() => d.remove(), 5000); }
// Detectores: janela de tempo, limite e cooldown, como no backend
function detect(e) {
  const R = S.rules;
  if (e.t === 'login' && !e.ok && R.brute_force.on) {
    const r = R.brute_force, n = S.ev.filter(x => x.ip === e.ip && x.t === 'login' && !x.ok && e.ts - x.ts <= r.win * 1000).length;
    if (n >= r.limit) raise('brute_force', e.ip, n, n >= r.limit * 4 ? 'critical' : n >= r.limit * 2 ? 'high' : 'medium', `${n} falhas de login em ${r.win}s`);
  }
  if (e.t === 'login' && !e.ok && R.cred_stuffing.on) {
    const r = R.cred_stuffing, n = new Set(S.ev.filter(x => x.ip === e.ip && x.t === 'login' && !x.ok && e.ts - x.ts <= r.win * 1000).map(x => x.user)).size;
    if (n >= r.limit) raise('cred_stuffing', e.ip, n, n >= r.limit * 3 ? 'critical' : 'high', `${n} usuários diferentes tentados em ${r.win}s`);
  }
  if (e.t === 'login' && e.ok && R.compromise.on) {
    const r = R.compromise, n = S.ev.filter(x => x.ip === e.ip && x.t === 'login' && !x.ok && e.ts - x.ts <= r.win * 1000).length;
    if (n >= r.limit) raise('compromise', e.ip, n, 'critical', `Login de ${e.user} bem-sucedido após ${n} falhas em ${r.win}s`);
  }
  if (e.t === 'port' && R.port_scan.on) {
    const r = R.port_scan, n = new Set(S.ev.filter(x => x.ip === e.ip && x.t === 'port' && e.ts - x.ts <= r.win * 1000).map(x => x.port)).size;
    if (n >= r.limit) raise('port_scan', e.ip, n, n >= r.limit * 2.5 ? 'critical' : 'high', `${n} portas diferentes em ${r.win}s`);
  }
}
function raise(type, ip, count, sev, msg) {
  const k = type + ip;
  if (S.last[k] && Date.now() - S.last[k] < 60000) return;
  if ((type === 'brute_force' || type === 'cred_stuffing') && S.al.some(a => (a.type === 'brute_force' || a.type === 'cred_stuffing') && a.ip === ip && a.type !== type && Date.now() - a.ts < 60000)) return;
  S.last[k] = Date.now();
  const a = { id: ++S.seq, type, ip, count, sev, msg, ts: Date.now(), open: false, res: false, inv: false, hist: [[Date.now(), 'Alerta gerado pela regra ' + TI[type]]] };
  if (S.notify && RANK[sev] >= 2) toast(`Alerta ${SEV[sev].toLowerCase()} enviado ao canal #seguranca: ${TI[type]} em ${ip}`);
  S.al.unshift(a); S.fresh = a.id;
  if (S.auto.on && sev === 'critical') S.blk.set(ip, { ts: Date.now(), why: type, exp: Date.now() + S.auto.minutes * 60000 });
  if (S.al.length > 60) S.al.pop();
  rList();
}
function emit(ev) { if (S.blk.has(ev.ip)) return; ev.ts = Date.now(); S.ev.push(ev); detect(ev); }

// Simulador de tráfego
function background() {
  if (S.paused) return;
  for (let i = rnd(1, 3); i > 0; i--) {
    const ip = rip(), r = Math.random();
    if (r < .8) emit({ ip, t: 'login', user: pick(USERS), ok: true });
    else if (r < .93) emit({ ip, t: 'login', user: pick(USERS), ok: false });
    else emit({ ip, t: 'port', port: pick([22, 80, 443, 8080, 3306]) });
  }
}
function attack(kind) {
  let ip; do { ip = rip(); } while (S.blk.has(ip));
  const total = kind === 'comp' ? 6 : rnd(14, 24); let i = 0;
  const t = setInterval(() => {
    if (S.blk.has(ip) || i >= total) return clearInterval(t);
    if (S.paused) return;
    if (kind === 'brute') emit({ ip, t: 'login', user: pick(['admin', 'root']), ok: false }); else if (kind === 'stuff') emit({ ip, t: 'login', user: pick(USERS.concat(ATK)), ok: false }); else if (kind === 'comp') emit({ ip, t: 'login', user: 'deploy', ok: i === 4 }); else emit({ ip, t: 'port', port: PORTS[i] || rnd(1, 65535) });
    i++;
  }, 220);
}

// Telas
function det(a) {
  const ev = S.ev.filter(x => x.ip === a.ip).slice(-4).reverse(), m = MT[a.type];
  return `<div class="det"><div class="dl"><p>${TIPS[a.type]}</p>` +
    `<div class="mt"><span class="tag">MITRE ${m[0]}</span><span class="tag">${m[1]}</span><span class="tag">${m[2]}</span><span class="tag">Risco do IP: ${risk(a.ip)}</span></div>` +
    `<ul>${ev.map(x => `<li>${hm(x.ts)}, ${lbl(x)}</li>`).join('')}</ul>` +
    `<div class="hist">${a.hist.slice().reverse().map(h => `<div><span>${hm(h[0])}</span>${esc(h[1])}</div>`).join('')}</div>` +
    `<div class="nt"><input type="text" maxlength="140" placeholder="Adicionar nota" aria-label="Nota sobre o alerta"><button class="btn" data-note="${a.id}">Salvar nota</button></div></div><div class="acts"><button class="btn" data-ip="${a.ip}">Ver IP</button>` +
    (S.blk.has(a.ip) || !can() ? '' : `<button class="btn p" data-block="${a.ip}" data-why="${a.type}" data-aid="${a.id}">Bloquear IP</button>`) +
    (a.inv || a.res ? '' : `<button class="btn" data-inv="${a.id}">Investigar</button>`) +
    (a.res ? '' : `<button class="btn" data-res="${a.id}">Marcar como resolvido</button>`) + '</div></div>';
}
function rows(list, none) {
  if (!list.length) return `<div class="empty">${none}</div>`;
  return list.map(a => { const [st, c] = stOf(a);
    return `<div class="tr al ${a.sev}${a.id === S.fresh ? ' new' : ''}" data-id="${a.id}" tabindex="0" role="button" aria-expanded="${a.open}">` +
      `<span class="pill">${SEV[a.sev]}</span><b>${TI[a.type]}</b><span>${a.ip}</span><span class="m">${esc(a.msg)}</span><time data-ts="${a.ts}">${ago(a.ts)}</time><span class="st ${c}">${st}</span>${a.open ? det(a) : ''}</div>`;
  }).join('');
}
const SORT = {
  ts: (a, b) => a.ts - b.ts,
  sev: (a, b) => RANK[a.sev] - RANK[b.sev],
  type: (a, b) => TI[a.type].localeCompare(TI[b.type]),
  ip: (a, b) => a.ip.localeCompare(b.ip, undefined, { numeric: true }),
  st: (a, b) => stOf(a)[0].localeCompare(stOf(b)[0]),
};
function rSort() { $$('[data-sort]').forEach(b => { b.dataset.dir = b.dataset.sort === S.sort.k ? String(S.sort.d) : ''; }); }
function rList() {
  if (document.activeElement && document.activeElement.closest && document.activeElement.closest('.nt')) { rBadges(); return; }
  if (S.view === 'overview') $('#recent').innerHTML = rows(S.al.slice(0, 5), (LIVE ? 'Nenhum alerta ainda. Ligue o simulador (SIMULATE=true) ou aponte o coletor de logs para este servidor.' : 'Nenhum alerta ainda. Use os botões no topo para provocar um ataque.'));
  if (S.view === 'alerts') {
    const f = S.f; let l = S.al.filter(a => (f.sev === 'all' || a.sev === f.sev) && (f.st === 'all' || stOf(a)[1] === f.st) && a.ip.includes(f.q) && (f.per === 'all' || Date.now() - a.ts <= +f.per * 60000));
    const cmp = SORT[S.sort.k];
    l = l.slice().sort((a, b) => S.sort.d * cmp(a, b) || b.ts - a.ts);
    const total = l.length; l = l.slice(0, f.n);
    $('#alerts').innerHTML = rows(l, S.al.length ? 'Nenhum alerta com esses filtros.' : 'Nenhum alerta ainda. Os detectores estão analisando o tráfego.') +
      (total > l.length ? `<div class="empty"><button class="btn" data-more>Mostrar mais (${total - l.length})</button></div>` : '');
  }
  if (S.view === 'incidents') rIncidents();
  S.fresh = null; rBadges(); if (S.view === 'overview') rKpi();
}
// Incidentes: alertas do mesmo IP com menos de 30 minutos entre um e outro viram um só
S.incOpen = new Set();
function incidents() {
  const by = {}, out = [];
  S.al.slice().sort((a, b) => a.ts - b.ts).forEach(a => { (by[a.ip] = by[a.ip] || []).push(a); });
  for (const [ip, list] of Object.entries(by)) {
    let cur = null;
    for (const a of list) {
      if (!cur || a.ts - cur.last > 30 * 60000) { cur = { ip, first: a.ts, last: a.ts, alerts: [] }; out.push(cur); }
      cur.alerts.push(a); cur.last = a.ts;
    }
  }
  out.forEach(i => { i.key = i.ip + '-' + i.first; i.sev = i.alerts.reduce((m, a) => RANK[a.sev] > RANK[m] ? a.sev : m, 'medium'); i.blocked = S.blk.has(i.ip); i.live = i.alerts.some(isOpen); });
  return out.sort((a, b) => b.last - a.last);
}
function rIncidents() {
  const l = incidents();
  $('#incl').innerHTML = l.length ? l.map(i => {
    const open = S.incOpen.has(i.key), rules = [...new Set(i.alerts.map(a => TI[a.type]))].join(', '), tech = [...new Set(i.alerts.map(a => MT[a.type] ? MT[a.type][0] : '?'))].join(', ');
    const st = i.blocked ? ['Bloqueado', 'b'] : i.live ? ['Aberto', 'o'] : ['Encerrado', 'r'];
    return `<div class="tr inc ${i.sev}" data-inc="${esc(i.key)}" tabindex="0" role="button" aria-expanded="${open}"><span class="pill">${SEV[i.sev]}</span><span data-ip="${i.ip}">${i.ip}</span>` +
      `<span class="m">${i.alerts.length} ${i.alerts.length === 1 ? 'alerta' : 'alertas'}: ${esc(rules)}. MITRE ${esc(tech)}</span><time data-ts="${i.last}">${ago(i.last)}</time><span class="st ${st[1]}">${st[0]}</span>` +
      (open ? `<div class="det"><div class="hist">${i.alerts.map(a => `<div><span>${hm(a.ts)}</span>${esc(TI[a.type])}: ${esc(a.msg)}</div>`).join('')}</div></div>` : '') + '</div>';
  }).join('') : '<div class="empty">Nenhum incidente ainda. Eles aparecem quando os detectores geram alertas.</div>';
}
function rBadges() { const n = S.al.filter(isOpen).length; $('#nbA').textContent = n || ''; $('#nbB').textContent = S.blk.size || ''; }
function rKpi() {
  const now = Date.now(), r = S.ev.filter(e => now - e.ts <= 60000), f = r.filter(e => e.t === 'login' && !e.ok).length, open = S.al.filter(isOpen);
  $('#kEv').textContent = r.length; $('#hEv').textContent = (r.length / 60).toFixed(1).replace('.', ',') + ' por segundo';
  $('#kFail').textContent = f; $('#hFail').textContent = (r.length ? Math.round(f / r.length * 100) : 0) + '% do tráfego';
  $('#kOpen').textContent = open.length; $('#hOpen').textContent = S.blk.size + (S.blk.size === 1 ? ' IP bloqueado' : ' IPs bloqueados');
  const top = open.reduce((m, a) => RANK[a.sev] > RANK[m] ? a.sev : m, 'none'), el = $('#kSev');
  el.textContent = top === 'none' ? 'Nenhuma' : SEV[top]; el.style.color = top === 'none' ? '' : `var(--${VR[top]})`;
  const c = { critical: 0, high: 0, medium: 0 }; S.al.forEach(a => c[a.sev]++);
  const tot = S.al.length;
  $('#sv').innerHTML = tot ? Object.keys(c).filter(k => c[k]).map(k => `<div style="flex:${c[k]};background:var(--${VR[k]})"></div>`).join('') : '';
  $('#sl').innerHTML = Object.keys(c).map(k => `<span style="--c:var(--${VR[k]})">${SEV[k]} ${c[k]}</span>`).join('');
}
function rChart() {
  const now = Date.now(), t = Array(60).fill(0), b = Array(60).fill(0);
  for (const e of S.ev) { const a = Math.floor((now - e.ts) / 1000); if (a < 0 || a > 59) continue; t[59 - a]++; if (e.t === 'login' && !e.ok) b[59 - a]++; }
  const sm = a => a.map((v, i) => ((a[i - 1] ?? v) + v + (a[i + 1] ?? v)) / 3), T = sm(t), B = sm(b), max = Math.max(6, Math.ceil(Math.max(...T)));
  const W = 720, H = 220, L = 32, ph = H - 36, pw = W - L - 8, X = i => L + i * pw / 59, Y = v => 12 + ph - v / max * ph;
  const ln = a => a.map((v, i) => (i ? 'L' : 'M') + X(i).toFixed(1) + ' ' + Y(v).toFixed(1)).join('');
  let s = '';
  for (let g = 0; g <= 3; g++) { const v = Math.round(max * g / 3), y = Y(v); s += `<line x1="${L}" x2="${W - 8}" y1="${y}" y2="${y}" stroke="var(--line)"/><text x="${L - 8}" y="${y + 4}" text-anchor="end" font-size="11" fill="var(--mute)">${v}</text>`; }
  for (const a of S.al) { const d = (now - a.ts) / 1000; if (d > 59) continue; const x = X(59 - d); s += `<line x1="${x}" x2="${x}" y1="12" y2="${Y(0)}" stroke="var(--${VR[a.sev]})" stroke-dasharray="3 3"/><circle cx="${x}" cy="12" r="3.5" fill="var(--${VR[a.sev]})"/>`; }
  s += `<path d="${ln(T)}L${X(59)} ${Y(0)}L${X(0)} ${Y(0)}Z" fill="var(--accent)" opacity=".10"/><path d="${ln(T)}" fill="none" stroke="var(--accent)" stroke-width="1.5" stroke-linejoin="round"/><path d="${ln(B)}" fill="none" stroke="var(--high)" stroke-width="1.5" stroke-linejoin="round"/>`;
  [['há 60s', 0, 'start'], ['há 30s', 29.5, 'middle'], ['agora', 59, 'end']].forEach(([x, i, an]) => s += `<text x="${X(i)}" y="${H - 6}" text-anchor="${an}" font-size="11" fill="var(--mute)">${x}</text>`);
  $('#chart').innerHTML = s;
}
function rIPs() {
  const now = Date.now(), m = {};
  for (const e of S.ev) { if (now - e.ts > 300000 || (e.t === 'login' && e.ok)) continue; (m[e.ip] = m[e.ip] || { ip: e.ip, n: 0 }).n++; }
  const arr = Object.values(m).map(x => ({ ...x, r: risk(x.ip) })).sort((a, b) => b.r - a.r).slice(0, 6);
  $('#ips').innerHTML = arr.length ? arr.map(x => { const c = x.r >= 70 ? 'crit' : x.r >= 40 ? 'high' : 'med'; return `<li><span data-ip="${x.ip}" class="lk">${x.ip}${S.blk.has(x.ip) ? '<span class="tag">bloqueado</span>' : ''}</span><div class="bar2"><div style="width:${x.r}%;background:var(--${c})"></div></div><b style="color:var(--${c})">${x.r}</b></li>`; }).join('') : '<li style="display:block" class="mu">Sem atividade suspeita por enquanto.</li>';
}
function rLog() {
  const f = S.ef, l = S.ev.slice(-150).reverse().filter(x => f === 'all' || (f === 'ok' && x.t === 'login' && x.ok) || (f === 'fail' && x.t === 'login' && !x.ok) || (f === 'port' && x.t === 'port')).slice(0, 60);
  $('#log').innerHTML = l.map(x => `<div class="ll${x.t === 'login' && !x.ok ? ' f' : ''}"><span>${hm(x.ts)}</span><span>${x.t === 'port' ? 'porta' : 'login'}</span><span>${x.ip}</span><span>${x.t === 'port' ? 'acesso à porta ' + x.port : esc(String(x.user)) + (x.ok ? ' autenticado' : ' falhou')}</span></div>`).join('') || '<div class="empty">Sem eventos para mostrar.</div>';
}
function rBlocks() {
  const l = [...S.blk.entries()].sort((a, b) => b[1].ts - a[1].ts);
  $('#blocks').innerHTML = l.length ? l.map(([ip, b]) => `<div class="tr k"><b data-ip="${ip}">${ip}</b><time data-ts="${b.ts}">${ago(b.ts)}</time><span>${TI[b.why] || 'Manual'}</span><span>${S.al.filter(a => a.ip === ip).length}</span><span class="mu">${b.exp ? 'em ' + Math.max(1, Math.round((b.exp - Date.now()) / 60000)) + ' min' : 'Permanente'}</span>${can() ? `<button class="btn" data-unb="${ip}">Desbloquear</button>` : ''}</div>`).join('') : '<div class="empty">Nenhum IP bloqueado. Abra um alerta e use Bloquear IP.</div>';
}
function rRules() {
  $('#rules').innerHTML = Object.entries(S.rules).filter(([k]) => RD[k]).map(([k, r]) => {
    const fl = RD[k][2] || '';
    return `<div class="rule"><div><b>${RD[k][0]}</b><p>${RD[k][1]}</p></div><div class="rc"><label><input type="checkbox" data-r="${k}" data-k="on" ${r.on ? 'checked' : ''}> Ativa</label>` +
      (fl === 'none' ? '' : `<label>${fl === 'nowin' ? 'IPs já usados' : 'Limite'} <input type="number" min="2" max="100" value="${r.limit}" data-r="${k}" data-k="limit"></label>`) +
      (fl ? '' : `<label>Janela (s) <input type="number" min="10" max="300" value="${r.win}" data-r="${k}" data-k="win"></label>`) + '</div></div>';
  }).join('');
  if (!can()) $$('#rules input').forEach(i => { i.disabled = true; });
}
function rAudit() { $('#auditl').innerHTML = S.audit.length ? S.audit.map(a => `<div class="tr a"><time>${hm(a[0])}</time><span>${esc(a[1])}</span></div>`).join('') : '<div class="empty">Nenhuma ação registrada ainda. Bloquear um IP, investigar um alerta ou mudar uma regra aparece aqui.</div>'; }
function rSettings() {
  const cfg = S.cfg || {}, on = cfg.notifications && cfg.notifications.configured;
  $('#np').innerHTML = `<div class="ph"><h2>Notificações</h2></div><div class="rule"><div><b>Alertas altos e críticos</b><p>${LIVE ? (on ? 'Enviadas por webhook ou Telegram, conforme o .env do servidor.' : 'Nenhum canal configurado. Defina WEBHOOK_URL (Slack) ou TELEGRAM_BOT_TOKEN e TELEGRAM_CHAT_ID no .env do servidor.') : 'Simula o envio de uma mensagem ao canal #seguranca quando uma regra dispara.'}</p></div>${LIVE ? '' : `<div class="rc"><label><input type="checkbox" data-s="notify" ${S.notify ? 'checked' : ''}> Ativas</label></div>`}</div>`;
  const ex = LIVE && cfg.allowlist && cfg.allowlist.length ? ' Nunca bloqueia: ' + esc(cfg.allowlist.join(', ')) + '.' : '';
  $('#auto').innerHTML = `<div class="ph"><h2>Resposta automática</h2></div><div class="rule"><div><b>Bloquear alertas críticos</b><p>Bloqueia o IP por um tempo e libera sozinho depois.${ex}</p></div><div class="rc"><label><input type="checkbox" data-s="auto" ${S.auto.on ? 'checked' : ''}> Ativa</label><label>Duração (min) <input type="number" min="1" max="1440" value="${S.auto.minutes}" data-s="min"></label></div></div>`;
  if (!can()) $$('#np input, #auto input').forEach(i => { i.disabled = true; });
}
function setting(el) {
  const k = el.dataset.s;
  if (k === 'notify') { S.notify = el.checked; return audit('Notificações ' + (S.notify ? 'ativadas' : 'desativadas')); }
  if (k === 'auto') S.auto.on = el.checked; else { S.auto.minutes = Math.min(1440, Math.max(1, Math.round(+el.value) || 1)); el.value = S.auto.minutes; }
  audit('Resposta automática ' + (S.auto.on ? 'ativa por ' + S.auto.minutes + ' min' : 'desativada'));
  if (LIVE) post('/api/settings', { autoBlock: S.auto }, 'PUT').catch(() => {});
}

// Ficha do IP
async function openIp(ip) {
  $('#ipd').hidden = false;
  let ev = S.ev.filter(x => x.ip === ip).slice(-40).reverse(), tot = null, repu = null, geo = null;
  if (LIVE) { try { const d = await get('/api/ips/' + ip); ev = d.events.map(mapEv); tot = d.totals; repu = d.reputation; geo = d.geo; } catch (_) { /* usa o que há na tela */ } }
  const al = S.al.filter(a => a.ip === ip), b = S.blk.get(ip), r = risk(ip);
  $('#ipc').innerHTML = `<h2 id="ipT">${esc(ip)}</h2>` +
    `<div class="mt"><span class="tag">Risco ${r}</span><span class="tag">${b ? 'Bloqueado' + (b.exp ? ' até ' + hm(b.exp) : '') : 'Não bloqueado'}</span>` +
    (tot ? `<span class="tag">${tot.events} eventos</span><span class="tag">${tot.failures} falhas</span>` : '') +
    (geo ? `<span class="tag">${esc(geo.name || geo.country)}</span>` : '') + (repu ? `<span class="tag">AbuseIPDB ${repu.score}%, ${repu.reports} relatos, ${esc(repu.country || '')}</span>` : '') + '</div>' +
    `<p class="mu">Alertas deste IP</p>` + (al.length ? al.map(a => `<div class="hist"><div><span>${hm(a.ts)}</span>${SEV[a.sev]}, ${TI[a.type]}: ${esc(a.msg)}</div></div>`).join('') : '<p class="mu">Nenhum alerta.</p>') +
    `<p class="mu" style="margin-top:12px">Eventos recentes</p><div class="lg">` + (ev.length ? ev.map(x => `<div class="ll${x.t === 'login' && !x.ok ? ' f' : ''}"><span>${hm(x.ts)}</span><span>${x.t === 'port' ? 'porta' : 'login'}</span><span>${x.t === 'port' ? 'porta ' + x.port : esc(x.user || '')}</span><span>${x.t === 'port' ? 'acesso' : x.ok ? 'autenticado' : 'falhou'}</span></div>`).join('') : '<div class="empty">Sem eventos.</div>') + '</div>' +
    `<div class="acts" style="margin-top:14px">${!b && can() ? `<button class="btn p" data-block="${esc(ip)}" data-why="manual" data-aid="">Bloquear IP</button>` : ''}<button class="btn" id="ipx">Fechar</button></div>`;
  $('#ipx').onclick = () => { $('#ipd').hidden = true; };
}
document.addEventListener('keydown', e => { if (e.key === 'Escape') $('#ipd').hidden = true; });
$('#ipd').addEventListener('click', e => { if (e.target.id === 'ipd') $('#ipd').hidden = true; });

// Usuários (só com servidor, só administrador)
async function rUsers() {
  const box = $('#users');
  if (!LIVE) { box.innerHTML = '<div class="empty">A gestão de usuários existe quando o painel está conectado ao servidor.</div>'; return; }
  const l = await get('/api/users').catch(() => null);
  if (!Array.isArray(l)) { box.innerHTML = '<div class="empty">Sem permissão para ver os usuários.</div>'; return; }
  box.innerHTML = '<div class="tb"><input id="nu" placeholder="Novo usuário" maxlength="32" aria-label="Novo usuário"><input id="npw" type="password" placeholder="Senha (mínimo 10 caracteres)" maxlength="128" aria-label="Senha"><select id="nr" aria-label="Perfil"><option value="analyst">Analista</option><option value="admin">Administrador</option></select><button class="btn p" data-uadd>Criar usuário</button></div>' +
    '<div class="tr u th"><span>Usuário</span><span>Perfil</span><span></span></div>' +
    l.map(u => `<div class="tr u"><b>${esc(u.username)}${u.locked ? '<span class="tag">travada</span>' : ''}</b><span>${u.role === 'admin' ? 'Administrador' : 'Analista'}</span><span class="acts">${u.locked ? `<button class="btn" data-uunl="${esc(u.username)}">Destravar</button>` : ''}<button class="btn" data-upw="${esc(u.username)}">Trocar senha</button><button class="btn" data-udel="${esc(u.username)}">Remover</button></span></div>`).join('');
}
async function rKeys() {
  const box = $('#keysl');
  if (!LIVE) { box.innerHTML = '<div class="empty">As chaves por fonte existem quando o painel está conectado ao servidor.</div>'; return; }
  const l = await get('/api/keys').catch(() => null);
  if (!Array.isArray(l)) { box.innerHTML = '<div class="empty">Sem permissão para ver as chaves.</div>'; return; }
  box.innerHTML = '<div class="tb"><input id="kn" placeholder="Nome da fonte (ex.: servidor-web)" maxlength="40" aria-label="Nome da fonte"><button class="btn p" data-kadd>Criar chave</button></div>' +
    '<div class="tr key th"><span>Fonte</span><span>Chave</span><span>Último uso</span><span></span></div>' +
    (l.length ? l.map(k => `<div class="tr key"><b>${esc(k.name)}</b><span class="mu">${esc(k.prefix)}…</span><span class="mu">${k.last_used ? ago(k.last_used) : 'nunca'}</span><span class="acts">${k.revoked ? '<span class="st b">Revogada</span>' : `<button class="btn" data-krev="${k.id}">Revogar</button>`}</span></div>`).join('') : '<div class="empty">Nenhuma chave criada. Crie uma para cada servidor ou coletor que enviar logs.</div>');
}
async function addKey() {
  const r = await post('/api/keys', { name: $('#kn').value.trim() }).catch(() => null);
  if (r && r.key) prompt('Copie a chave agora. Ela não será mostrada de novo (use no cabeçalho x-api-key ou na variável API_KEY do coletor):', r.key);
  else toast(r && r.error ? r.error : 'Não foi possível criar a chave');
  rKeys();
}
async function revokeKey(id) {
  if (!confirm('Revogar esta chave? Quem a usa deixa de conseguir enviar logs.')) return;
  await post('/api/keys/' + id, null, 'DELETE').catch(() => null);
  toast('Chave revogada'); rKeys();
}
async function unlockUser(name) {
  const r = await post('/api/users/' + encodeURIComponent(name) + '/unlock').catch(() => null);
  toast(r && r.error ? r.error : 'Conta destravada'); rUsers();
}
async function addUser() {
  const r = await post('/api/users', { username: $('#nu').value.trim(), password: $('#npw').value, role: $('#nr').value }).catch(() => null);
  toast(r && r.error ? r.error : 'Usuário criado'); rUsers();
}
async function userAct(kind, name) {
  if (kind === 'pw') {
    const p = prompt('Nova senha para ' + name + ' (mínimo 10 caracteres)'); if (!p) return;
    const r = await post('/api/users/' + encodeURIComponent(name), { password: p }, 'PATCH').catch(() => null);
    toast(r && r.error ? r.error : 'Senha alterada');
  } else if (confirm('Remover o usuário ' + name + '?')) {
    const r = await post('/api/users/' + encodeURIComponent(name), null, 'DELETE').catch(() => null);
    toast(r && r.error ? r.error : 'Usuário removido');
  }
  rUsers();
}
function setView(v) {
  S.view = v;
  $$('.nav button').forEach(b => { b.classList.toggle('on', b.dataset.v === v); if (b.dataset.v === v) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current'); });
  ['overview', 'alerts', 'incidents', 'events', 'blocks', 'rules', 'audit', 'users', 'keys'].forEach(k => { const el = $('#v-' + k); if (el) el.hidden = k !== v; });
  $('#ttl').textContent = META[v][0]; $('#sub').textContent = META[v][1];
  rList(); if (v === 'overview') { rKpi(); rChart(); rIPs(); } if (v === 'events') rLog(); if (v === 'blocks') rBlocks(); if (v === 'rules') { rRules(); rSettings(); } if (v === 'users') rUsers(); if (v === 'keys') rKeys(); if (v === 'incidents') rIncidents();
  if (v === 'audit') { if (LIVE) loadAudit().then(rAudit).catch(() => {}); rAudit(); }
  window.scrollTo(0, 0);
}

document.addEventListener('click', e => {
  const t = e.target, v = t.closest('[data-v]'), bl = t.closest('[data-block]'), rs = t.closest('[data-res]'), iv = t.closest('[data-inv]'), nt = t.closest('[data-note]'), ub = t.closest('[data-unb]');
  const al = id => S.al.find(a => a.id === +id);
  const so = t.closest('[data-sort]'), more = t.closest('[data-more]');
  if (so) { const k = so.dataset.sort; S.sort = { k, d: S.sort.k === k ? -S.sort.d : (k === 'ts' || k === 'sev' ? -1 : 1) }; S.f.n = 25; rSort(); return rList(); }
  if (more) { S.f.n += 25; return rList(); }
  const inc = t.closest('[data-inc]'), ka = t.closest('[data-kadd]'), kr = t.closest('[data-krev]'), uu = t.closest('[data-uunl]');
  const ipb = t.closest('[data-ip]'), ua = t.closest('[data-uadd]'), up = t.closest('[data-upw]'), ud = t.closest('[data-udel]');
  if (ipb) return openIp(ipb.dataset.ip);
  if (inc && !t.closest('.det')) { const k = inc.dataset.inc; S.incOpen.has(k) ? S.incOpen.delete(k) : S.incOpen.add(k); return rIncidents(); }
  if (ka) return addKey();
  if (kr) return revokeKey(kr.dataset.krev);
  if (uu) return unlockUser(uu.dataset.uunl);
  if (ua) return addUser();
  if (up) return userAct('pw', up.dataset.upw);
  if (ud) return userAct('del', ud.dataset.udel);
  if (v) return setView(v.dataset.v);
  if (bl) { const ip = bl.dataset.block; S.blk.set(ip, { ts: Date.now(), why: bl.dataset.why }); if (LIVE) post('/api/blocks', { ip, reason: bl.dataset.why }).then(r => { if (r && r.error) { S.blk.delete(ip); toast(r.error); rAfter(); } }).catch(() => {}); act(al(bl.dataset.aid), 'IP bloqueado'); return rAfter(); }
  if (rs) { const a = al(rs.dataset.res); a.res = true; if (LIVE) patch(a.id, 'resolve'); act(a, 'Marcado como resolvido'); return rAfter(); }
  if (iv) { const a = al(iv.dataset.inv); a.inv = true; if (LIVE) patch(a.id, 'investigate'); act(a, 'Investigação iniciada'); return rAfter(); }
  if (nt) { const x = nt.previousElementSibling.value.trim(); if (!x) return; if (LIVE) patch(+nt.dataset.note, 'note', x); act(al(nt.dataset.note), 'Nota: ' + x); document.activeElement.blur(); return rAfter(); }
  if (ub) { S.blk.delete(ub.dataset.unb); if (LIVE) post('/api/blocks/' + ub.dataset.unb, null, 'DELETE').catch(() => {}); audit('IP desbloqueado (' + ub.dataset.unb + ')'); rBlocks(); return rAfter(); }
  const row = t.closest('.al');
  if (row && !t.closest('.det')) { const a = al(row.dataset.id); a.open = !a.open; rList(); }
});
function rAfter() { rList(); rIPs(); rKpi(); if (S.view === 'blocks') rBlocks(); }
document.addEventListener('keydown', e => {
  if (e.key === 'Enter' && e.target.closest && e.target.closest('.nt')) return e.target.nextElementSibling.click();
  if (e.target.matches('input,select,textarea') || e.metaKey || e.ctrlKey || e.altKey) return;
  const k = ['overview', 'alerts', 'incidents', 'events', 'blocks', 'rules', 'audit', 'users', 'keys'][+e.key - 1];
  if (k) { if ((k !== 'audit' && k !== 'users' && k !== 'keys') || can()) setView(k); } else if (e.key === '/') { e.preventDefault(); setView('alerts'); $('#q').focus(); }
});
$('#bTheme').onclick = () => { const r = document.documentElement; r.dataset.theme = r.dataset.theme === 'light' ? 'dark' : 'light'; };
document.addEventListener('keydown', e => { if ((e.key === 'Enter' || e.key === ' ') && (e.target.classList.contains('al') || e.target.classList.contains('inc'))) { e.preventDefault(); e.target.click(); } });
$('#q').oninput = e => { S.f.q = e.target.value.trim(); S.f.n = 25; rList(); };
$('#fs').onchange = e => { S.f.sev = e.target.value; S.f.n = 25; rList(); };
$('#ft').onchange = e => { S.f.st = e.target.value; S.f.n = 25; rList(); };
$('#fp').onchange = e => { S.f.per = e.target.value; S.f.n = 25; rList(); };
$('#fe').onchange = e => { S.ef = e.target.value; rLog(); };
document.addEventListener('change', e => {
  const d = e.target.dataset; if (d.s) return setting(e.target); if (!d.r) return;
  const v = d.k === 'on' ? e.target.checked : Math.min(+e.target.max, Math.max(+e.target.min, +e.target.value || +e.target.min));
  S.rules[d.r][d.k] = v; if (d.k !== 'on') e.target.value = v;
  if (LIVE) post('/api/rules', S.rules, 'PUT').catch(() => {});
  audit(`Regra ${RD[d.r][0]} alterada (${d.k === 'on' ? (v ? 'ativada' : 'desativada') : d.k === 'limit' ? 'limite ' + v : 'janela ' + v + 's'})`);
});
const run = k => LIVE ? post('/api/simulate', { kind: k }).then(r => { if (r && r.error) toast(r.error); }).catch(() => toast('Sem conexão com o servidor')) : attack(k);
$('#bCsv').onclick = () => {
  const q = v => '"' + String(v).replace(/"/g, '""') + '"';
  const rows = [['id', 'detectado_em', 'regra', 'gravidade', 'ip', 'detalhe', 'status', 'tecnica_mitre']].concat(S.al.map(a => [a.id, new Date(a.ts).toISOString(), TI[a.type], SEV[a.sev], a.ip, a.msg, stOf(a)[0], MT[a.type][0]]));
  const url = URL.createObjectURL(new Blob(['\ufeff' + rows.map(r => r.map(q).join(',')).join('\n')], { type: 'text/csv;charset=utf-8' }));
  const l = document.createElement('a'); l.href = url; l.download = 'alertas-mini-soc.csv'; l.click(); URL.revokeObjectURL(url);
};
$('#bBrute').onclick = () => run('brute');
$('#bScan').onclick = () => run('scan');
$('#bStuff').onclick = () => run('stuff');
$('#bComp').onclick = () => run('comp');
$('#bPrint').onclick = () => window.print();
$('#bPause').onclick = () => {
  S.paused = !S.paused;
  $('#bPause').textContent = S.paused ? 'Retomar simulação' : 'Pausar simulação';
  $('#live').textContent = S.paused ? 'Simulação pausada' : 'Simulação em andamento';
};

function startSim() {
  setInterval(background, 700);
  setInterval(() => { if (!S.paused) attack(pick(['brute', 'stuff', 'scan', 'comp'])); }, 17000);
  setTimeout(() => attack('brute'), 2500);
}

// Modo ao vivo: login, REST para o estado inicial e WebSocket para o que acontece depois
const mapAlert = a => ({ id: a.id, type: a.type, ip: a.ip, count: a.count, sev: a.severity, msg: a.message, ts: a.ts, open: false,
  res: a.status === 'resolved', inv: a.status === 'investigating',
  hist: (a.history || [{ ts: a.ts, text: 'Alerta gerado pela regra ' + TI[a.type] }]).map(h => [h.ts, h.text]) });
const mapEv = e => ({ ts: e.ts, ip: e.ip, t: e.type === 'login' ? 'login' : 'port', ok: !!e.success, user: e.username, port: e.port });
const loadAudit = () => get('/api/audit').then(r => { if (Array.isArray(r)) S.audit = r.map(x => [x.ts, `${x.username}: ${x.action}${x.detail ? ' (' + x.detail + ')' : ''}`]); });

async function load() {
  const [al, bl, ru, cfg] = await Promise.all(['/api/alerts?limit=60', '/api/blocks', '/api/rules', '/api/settings'].map(u => get(u)));
  S.cfg = cfg; S.auto = cfg.autoBlock;
  const opened = new Set(S.al.filter(x => x.open).map(x => x.id));
  S.al = al.map(mapAlert); S.al.forEach(x => { x.open = opened.has(x.id); });
  S.blk = new Map(bl.map(x => [x.ip, { ts: x.ts, why: x.reason, exp: x.expires_at }])); S.rules = ru;
  setView(S.view);
}
function connect() {
  if (!TOKEN) return;
  if (WSREF) { WSREF.onclose = null; WSREF.close(); }
  const ws = WSREF = new WebSocket(API.replace(/^http/, 'ws') + '/ws?token=' + encodeURIComponent(TOKEN));
  ws.onopen = () => { $('#live').textContent = 'Conectado ao servidor'; load().catch(() => {}); };
  ws.onclose = () => {
    if (ws !== WSREF) return;
    $('#live').textContent = 'Sem conexão com o servidor, tentando de novo';
    get('/api/auth/me').catch(() => {}); // se o login expirou, volta para a tela de entrada
    setTimeout(connect, 3000);
  };
  ws.onmessage = m => {
    const { kind, data } = JSON.parse(m.data);
    if (kind === 'event') S.ev.push(mapEv(data));
    else if (kind === 'alert') {
      const x = mapAlert(data); S.al.unshift(x); S.fresh = x.id; if (S.al.length > 60) S.al.pop();
      if (RANK[x.sev] >= 2) toast(`Novo alerta ${SEV[x.sev].toLowerCase()}: ${TI[x.type]} em ${x.ip}`);
      rList();
    } else if (kind === 'alert_update') {
      const n = mapAlert(data), x = S.al.find(y => y.id === n.id);
      if (x) { x.res = n.res; x.inv = n.inv; x.hist = n.hist; rList(); }
    } else if (kind === 'block') { S.blk.set(data.ip, { ts: data.ts, why: data.reason, exp: data.expires_at }); rAfter(); }
    else if (kind === 'unblock') { S.blk.delete(data.ip); rAfter(); }
  };
}

// Login
function showLogin() { $('#login').hidden = false; $('#lp').value = ''; $('#lu').focus(); }
let REFRESH = null;
const refresh = () => post('/api/auth/refresh').then(r => { if (r && r.token) { TOKEN = r.token; sessionStorage.setItem('soc_token', TOKEN); } }).catch(() => {});
function logout() {
  clearInterval(REFRESH);
  TOKEN = ''; ME = null; sessionStorage.removeItem('soc_token');
  if (WSREF) { WSREF.onclose = null; WSREF.close(); WSREF = null; }
  showLogin();
}
function enter() {
  $('#login').hidden = true;
  $('#who').hidden = false; $('#bOut').hidden = false; $('#bOutAll').hidden = false; $('#bPwd').hidden = false;
  clearInterval(REFRESH); REFRESH = setInterval(refresh, 20 * 60000);
  $('#who').textContent = ME.username + ' (' + (ME.role === 'admin' ? 'administrador' : 'analista') + ')';
  $$('.admin-only').forEach(el => { el.hidden = !can(); });
  connect();
}
async function doLogin() {
  $('#le').textContent = '';
  try {
    const r = await fetch(API + '/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: $('#lu').value.trim(), password: $('#lp').value }) });
    const d = await r.json();
    if (!r.ok) { $('#le').textContent = d.error || 'Não foi possível entrar'; return; }
    TOKEN = d.token; ME = d.user; sessionStorage.setItem('soc_token', TOKEN); enter();
  } catch (_) { $('#le').textContent = 'Servidor indisponível'; }
}
$('#lb').onclick = doLogin;
$('#lp').onkeydown = e => { if (e.key === 'Enter') doLogin(); };
$('#bOut').onclick = logout;
$('#bOutAll').onclick = async () => {
  if (!confirm('Encerrar todas as sessões desta conta, inclusive em outros navegadores?')) return;
  await post('/api/auth/logout-all').catch(() => {}); logout();
};
$('#bPwd').onclick = async () => {
  const cur = prompt('Senha atual:'); if (!cur) return;
  const nxt = prompt('Nova senha (mínimo de 10 caracteres):'); if (!nxt) return;
  const r = await post('/api/auth/password', { current: cur, next: nxt }).catch(() => null);
  if (r && r.ok) { toast('Senha alterada. Entre de novo.'); logout(); } else toast(r && r.error ? r.error : 'Não foi possível trocar a senha');
};

// Descobre sozinho se há um servidor: no mesmo endereço (Docker), em localhost:3000 (desenvolvimento) ou nenhum (demo)
async function detectApi() {
  const q = new URLSearchParams(location.search).get('api');
  const local = ['localhost', '127.0.0.1'].includes(location.hostname) ? 'http://localhost:3000' : null;
  for (const c of [q, location.origin, local]) {
    if (!c || !c.startsWith('http')) continue;
    try { const r = await fetch(c + '/api/health'); if (r.ok && (await r.json()).status === 'ok') return c; } catch (_) { /* tenta o próximo */ }
  }
  return '';
}
async function boot() {
  setView('overview');
  API = await detectApi(); LIVE = !!API;
  if (!LIVE) return startSim();
  $('#bPause').hidden = true;
  $('.foot').textContent = 'Conectado à API Express: eventos, alertas, bloqueios e auditoria chegam por REST e WebSocket.';
  TOKEN = sessionStorage.getItem('soc_token') || '';
  if (TOKEN) { try { ME = await get('/api/auth/me'); return enter(); } catch (_) { /* sessão expirada */ } }
  showLogin();
}

setInterval(() => {
  const now = Date.now(); S.ev = S.ev.filter(e => now - e.ts <= 300000);
  if (!LIVE) for (const [k, b] of S.blk) if (b.exp && b.exp < now) S.blk.delete(k);
  $('#clock').textContent = hm(now);
  if (S.view === 'overview') { rKpi(); rChart(); rIPs(); } if (S.view === 'events' && !S.paused) rLog();
  $$('time[data-ts]').forEach(t => t.textContent = ago(+t.dataset.ts));
}, 1000);

$('#clock').textContent = hm(Date.now());
boot();
