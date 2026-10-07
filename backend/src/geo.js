// País do IP, se GEOIP_DB apontar para um arquivo GeoLite2-Country.mmdb (gratuito, exige conta na MaxMind)
// e o pacote opcional "maxmind" estiver instalado. Sem isso, devolve null.
let readerPromise = null;

function open() {
  if (readerPromise) return readerPromise;
  const file = process.env.GEOIP_DB;
  if (!file) return (readerPromise = Promise.resolve(null));
  try {
    readerPromise = require('maxmind').open(file).catch(() => null);
  } catch (_) {
    readerPromise = Promise.resolve(null);
  }
  return readerPromise;
}

async function geo(ip) {
  const reader = await open();
  if (!reader) return null;
  try {
    const d = reader.get(ip);
    if (!d || !d.country) return null;
    const names = d.country.names || {};
    return { country: d.country.iso_code, name: names['pt-BR'] || names.en || d.country.iso_code };
  } catch (_) {
    return null;
  }
}

module.exports = { geo };
