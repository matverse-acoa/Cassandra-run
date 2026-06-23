# Freebuff — Política de Segurança Defensiva

## Perfil obrigatório

**MODO: SECURITY-ONLY / DEFENSIVE OBSERVABILITY**

Este repositório permite agente de programação somente para observação defensiva, verificação e remediação controlada. O agente não é autoridade de merge, produção ou acesso a segredos.

## Operações permitidas

- Auditar código, dependências, permissões, workflows, containers e configurações.
- Executar testes, lint, análise estática, verificação de integridade e scanners aprovados.
- Ler logs e métricas que já estejam autorizados no repositório ou ambiente local.
- Criar patch mínimo somente em branch `security/` e abrir PR.
- Produzir evidência: severidade, reprodução, arquivos afetados, impacto, patch, testes e rollback.

## Operações bloqueadas

- Push para `main`, merge, deploy, migração destrutiva, exclusão em massa ou rotação de credencial.
- Exploração, enumeração de rede, persistência, spyware, keylogger, RAT, bypass, exfiltração ou coleta oculta.
- Leitura, cópia, log ou transmissão de senha, token, chave, cookie, `.env` ou dado pessoal.
- Mudança de API pública, autenticação, contrato financeiro ou política normativa sem PR específico e revisão humana.

## Gates

- `PASS`: achado reproduzível, patch mínimo e validações aplicáveis aprovadas.
- `HOLD`: autorização, evidência ou teste insuficiente.
- `BLOCK`: ação fora do escopo, segredo exposto ou risco não autorizado.
- `ESCALATE`: integridade, segurança ou evidência comprometida.

## Regra de saída

Sem evidência reproduzível, trate como hipótese. Sem teste executado, não declare correção. Sem revisão humana, não integre mudança sensível.
