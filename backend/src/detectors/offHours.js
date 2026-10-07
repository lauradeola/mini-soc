const rules = require('../rules');
const { raiseAlert } = require('../alerts');

// Horário de trabalho no formato "07-20" (variável WORK_HOURS, no fuso do servidor)
function workHours() {
  const m = /^(\d{1,2})-(\d{1,2})$/.exec(process.env.WORK_HOURS || '07-20');
  return m ? [Math.min(23, +m[1]), Math.min(24, +m[2])] : [7, 20];
}

function checkOffHours(ev) {
  if (!rules.off_hours.on || ev.type !== 'login' || !ev.success) return null;
  const [start, end] = workHours();
  const d = new Date(ev.ts), h = d.getHours();
  if (h >= start && h < end) return null;
  const hhmm = `${String(h).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
  return raiseAlert(ev, 'off_hours', 'medium', 1, `Login de "${ev.username}" às ${hhmm}, fora do horário (${start}h às ${end}h)`);
}

module.exports = { checkOffHours, workHours };
