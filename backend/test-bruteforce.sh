#!/usr/bin/env bash
# Envia 6 logins falhos do mesmo IP pela API de ingestão (a mesma que um sistema real usaria).
# Uso: API_KEY=sua-chave bash test-bruteforce.sh
KEY="${API_KEY:?defina API_KEY, igual ao do .env}"
for i in 1 2 3 4 5 6; do
  curl -s -X POST http://localhost:3000/api/logs \
    -H "Content-Type: application/json" \
    -H "x-api-key: $KEY" \
    -d '{"ip":"203.0.113.50","type":"login","username":"admin","success":false}'
  echo
done
echo "Abra o painel: o alerta de força bruta deve aparecer."
