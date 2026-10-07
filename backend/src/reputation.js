const cache = new Map();
const TTL_MS = 3_600_000;

// Consulta opcional ao AbuseIPDB (guarda o resultado por 1 hora). Sem chave ou com erro, devolve null.
async function reputation(ip) {
  const key = process.env.ABUSEIPDB_KEY;
  if (!key) return null;
  const hit = cache.get(ip);
  if (hit && Date.now() - hit.at < TTL_MS) return hit.data;
  try {
    const r = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`, {
      headers: { Key: key, Accept: 'application/json' },
      signal: AbortSignal.timeout(5000),
    });
    if (!r.ok) return null;
    const d = (await r.json()).data;
    const data = { score: d.abuseConfidenceScore, reports: d.totalReports, country: d.countryCode, isp: d.isp };
    cache.set(ip, { at: Date.now(), data });
    return data;
  } catch (_) {
    return null;
  }
}

module.exports = { reputation };
