# Modelo de ameaças

Este documento diz o que o Mini SOC protege, contra quem, e onde ele **não** protege. Segurança honesta começa por aqui.

## O que há para proteger

- **Os dados**: eventos de login, alertas e a lista de bloqueios mostram a atividade do ambiente monitorado.
- **As ações**: quem pode bloquear IPs ou mudar regras controla a resposta a incidentes.
- **Os acessos**: contas, senhas e chaves de API.

## Quem pode atacar e como

| Ameaça | O que o projeto faz | O que sobra |
|---|---|---|
| Adivinhar senhas do painel | Limite de 10 tentativas por minuto por IP, conta travada por 15 min após 5 erros seguidos, senhas com scrypt e sal único, mesma resposta para usuário inexistente e senha errada | Quem trava a conta de alguém de propósito causa negação de serviço por até 15 min. O administrador pode destravar |
| Roubo de token | Token de 8 h, renovação, "encerrar todas as sessões" e troca de senha derrubam os tokens antigos. Remover ou rebaixar um usuário vale na hora, porque o perfil é lido do banco a cada chamada | O token fica no `sessionStorage` do navegador. Um XSS ainda poderia lê-lo |
| XSS no painel | Todo texto vindo de logs (usuário, mensagem, nomes) é escapado antes de ir para a tela. CSP do Helmet nas respostas do servidor | Quem abre o painel por outro servidor (Live Server) não tem a CSP |
| Um analista fazendo o que só o administrador pode | O servidor confere o perfil em cada rota. Esconder botões na tela é só conforto | Nenhuma conhecida |
| Enviar logs falsos | Chave de API obrigatória, uma por fonte e revogável. Validação de IP, tipos, tamanho e limite de 10 kB por requisição | Quem tem uma chave válida pode enviar dados falsos até ser revogada |
| Invasão do WebSocket | Exige token válido e origem permitida. Batimento derruba conexões mortas | Sem TLS, o token trafega em texto: use HTTPS em produção |
| Injeção de SQL | Todas as consultas usam parâmetros (`?`) | Nenhuma conhecida |
| Vazar segredos | `.env` fora do Git, chaves de API guardadas só como hash, URLs de webhook nunca vão para os logs | O arquivo `.env` precisa de permissões corretas no servidor |
| Bloquear o próprio IP | `ALLOWLIST`: IPs que nunca são bloqueados, nem pela resposta automática | Lista mantida à mão |

## O que este projeto não faz

- **Não é um IDS de rede**: ele analisa eventos de log enviados a ele, não o tráfego.
- **Não impede o ataque**: o bloqueio é uma lista dentro do sistema. Para barrar de verdade, outra peça (firewall, fail2ban) precisa ler essa lista.
- **Não tem 2FA**: o login é só usuário e senha.
- **O banco não é criptografado em repouso**: proteja o disco e os backups.
- **Detectores por limiar** pegam padrões simples. Um atacante lento e distribuído passa abaixo dos limites.
- **IPs podem ser falsificados** na origem dos logs: o que se vê é o que o sistema de origem registrou.

## Boas práticas ao publicar

1. Use HTTPS (proxy reverso) e defina `JWT_SECRET`.
2. Defina senhas fortes para `ADMIN_PASSWORD` e `ANALYST_PASSWORD`, ou anote as geradas na primeira execução.
3. Crie uma chave de API por fonte e revogue as que não usar.
4. Use `ALLOWLIST` com o seu IP e desligue `SIMULATE`.
5. Faça backup (`BACKUP_DIR`) e guarde as cópias fora do servidor.
