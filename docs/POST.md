# Rascunho de post: o que aprendi montando um mini SOC

Montei um painel de operações de segurança do zero, que detecta ataques em tempo real. Não queria só um painel bonito com dados de mentira, queria que as decisões de segurança fossem de verdade. Conto aqui as que mais me ensinaram.

**1. Detectar é fácil, não gerar ruído é difícil.** Os primeiros detectores disparavam alerta para tudo. O que resolveu foi pensar em cooldown (não repetir o mesmo alerta por um minuto), em precedência (credential stuffing é mais específico que força bruta, então ele ganha) e em só avisar "login de IP novo" quando a conta já tem histórico.

**2. O sinal mais importante não é o ataque, é o acesso depois dele.** Cinco senhas erradas são rotina. Cinco erros seguidos de um acerto na mesma conta é invasão. Esse detector é o único que gera alerta crítico por padrão.

**3. Esconder o botão não é controle de acesso.** O analista não vê "Bloquear IP" na tela, mas o que importa é o servidor recusar a chamada. Todo perfil é checado no servidor, e o perfil é lido do banco a cada requisição, então remover um usuário vale na hora.

**4. Bloquear conta também é uma arma contra você.** Travar a conta depois de 5 erros impede adivinhação de senha, mas permite que alguém trave a conta de outra pessoa de propósito. Escolhi um travamento curto, que se desfaz sozinho, e um botão para o administrador destravar. Está no modelo de ameaças.

**5. Todo texto que vem de fora é hostil.** Nomes de usuário vêm dos logs, e quem manda o log controla o texto. Escapar tudo antes de colocar na tela evita XSS por esse caminho.

**6. Escrever o que o projeto não faz.** O arquivo `docs/THREAT_MODEL.md` lista o que o sistema não protege. Foi o documento que mais me fez pensar.

No fim, o que mais me ensinou foi tratar o painel como um sistema que também pode ser atacado. Quem monitora precisa ser tão cuidadoso quanto quem é monitorado.

Código e demonstração: https://github.com/lauradeola/mini-soc
