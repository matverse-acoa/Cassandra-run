# Cassandra-run — Sovereign Runtime Node

Cassandra-run é o **runtime soberano** do MatVerse.

Ele executa ações **somente após aprovação explícita**
de um kernel normativo (PBSE) e registra todos os efeitos
em um ledger imutável.

---

## O que este repositório faz

- Executa ações aprovadas
- Escreve registros append-only
- Garante replay determinístico
- Expõe API mínima para observação

---

## O que este repositório NÃO faz

- Não define métricas
- Não decide políticas
- Não corrige dados científicos
- Não executa sem registro
- Não “confia” em contexto implícito

---

## Regime Arquitetural

**REGIME: RUNTIME**

Aqui, falha é bloqueio.
Ausência de prova é negação.

---

## Princípios

- Fail-closed
- Append-only
- Auditável por padrão
- Separação total entre decisão e execução

---

## Papel Sistêmico

Se este repositório falha,
o sistema inteiro **para**.

Ele é órgão vital, não experimento.
