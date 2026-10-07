# Política de segurança

## Versões com suporte

Só a versão mais recente (branch `main`) recebe correções.

## Como reportar uma vulnerabilidade

Não abra uma issue pública. Use o recurso **Security → Report a vulnerability** do repositório no GitHub (relatório privado) e descreva:

- o que acontece e qual o impacto
- os passos para reproduzir
- a versão ou o commit testado

Você deve receber uma resposta em alguns dias. Depois da correção, o problema pode ser divulgado com o devido crédito.

## Escopo

Veja em [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) o que o projeto protege e o que ele declara não proteger. Itens listados lá como limites conhecidos não são considerados vulnerabilidades.

## Antes de publicar uma instância

Use HTTPS, defina `JWT_SECRET` e senhas fortes, desligue `SIMULATE` e use uma chave de API por fonte de logs.
