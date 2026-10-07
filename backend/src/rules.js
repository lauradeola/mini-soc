const { load } = require('./config');

// Regras de detecção. O que for alterado na tela Regras fica salvo no banco.
module.exports = load('rules', {
  brute_force:   { on: true,  limit: 5, win: 60 },
  cred_stuffing: { on: true,  limit: 4, win: 60 },
  compromise:    { on: true,  limit: 3, win: 120 },
  port_scan:     { on: true,  limit: 8, win: 30 },
  new_ip:        { on: true,  limit: 2, win: 0 },  // limit = IPs que a conta já usou antes de avisar
  off_hours:     { on: false, limit: 0, win: 0 },  // horário definido por WORK_HOURS (ex.: 07-20)
});
