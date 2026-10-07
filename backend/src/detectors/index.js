const { checkBruteForce } = require('./bruteForce');
const { checkCredStuffing } = require('./credStuffing');
const { checkPortScan } = require('./portScan');
const { checkCompromise } = require('./compromise');
const { checkNewIp } = require('./newLocation');
const { checkOffHours } = require('./offHours');

// Credential stuffing vem antes: é mais específico que força bruta.
module.exports = [checkCredStuffing, checkBruteForce, checkCompromise, checkNewIp, checkOffHours, checkPortScan];
