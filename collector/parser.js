// Converte linhas do sshd (auth.log) em eventos da API do Mini SOC.
// Só conta "Failed" e "Accepted", para não duplicar com as linhas "Invalid user".
const FAIL = /Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+) port \d+/;
const OK = /Accepted (?:password|publickey|keyboard-interactive\/pam) for (\S+) from (\S+) port \d+/;

function parseLine(line) {
  let m = FAIL.exec(line);
  if (m) return { ip: m[2], type: 'login', username: m[1].slice(0, 64), success: false };
  m = OK.exec(line);
  if (m) return { ip: m[2], type: 'login', username: m[1].slice(0, 64), success: true };
  return null;
}

module.exports = { parseLine };
