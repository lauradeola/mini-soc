// Barramento de eventos interno. No passo do WebSocket, é aqui que
// o servidor vai "ouvir" os alertas novos e transmiti-los ao frontend.
const { EventEmitter } = require('events');
module.exports = new EventEmitter();
