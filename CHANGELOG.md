# Changelog

## 1.0.0

Primeira versão completa.

- Detectores: força bruta, credential stuffing, acesso após falhas, varredura de portas, login de novo IP e login fora do horário
- MITRE ATT&CK em cada alerta e pontuação de risco por IP
- Incidentes: alertas do mesmo IP agrupados em uma só história
- Login com perfis (administrador e analista), JWT, bloqueio de conta após tentativas seguidas e encerramento de sessões
- Chaves de API por fonte de logs, que podem ser revogadas separadamente
- Resposta automática com bloqueio temporário e lista de IPs protegidos
- Auditoria gravada no servidor; regras e configurações salvas no banco
- Coletor de logs do SSH, notificações por webhook e Telegram, reputação do IP e país (opcionais)
- Métricas Prometheus, logs estruturados, backup diário, retenção de dados e encerramento limpo
- Painel em tempo real por WebSocket, tema escuro e claro, exportação CSV e relatório para impressão
- Testes de detectores, autenticação e API; teste de ponta a ponta no navegador; CI no GitHub Actions
