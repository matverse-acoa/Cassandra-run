# Cassandra-MatVerse

Cassandra-MatVerse é um **nó soberano de decisão computacional** projetado para operar como infraestrutura de verdade operacional.

O sistema combina:
- ledger imutável,
- validação determinística,
- execução governada por métricas de risco,
- e infraestrutura de produção auditável.

Não é um framework experimental.  
É um **runtime de decisão verificável**.

---

## Princípios

- **Fail-closed**: ausência de prova bloqueia execução  
- **Append-only**: nenhuma mutação silenciosa  
- **Auditável por padrão**: tudo deixa rastro  
- **Separação clara**: decisão ≠ execução ≠ armazenamento  

---

## Arquitetura

```
┌────────────┐
│   API RPC  │  ← FastAPI (auth + rate limit)
└─────┬──────┘
      │
┌─────▼──────┐
│ Ω-Gate     │  ← decisão determinística (Ψ, CVaR)
└─────┬──────┘
      │
┌─────▼──────┐
│ Ledger     │  ← append-only + snapshot atômico
└─────┬──────┘
      │
┌─────▼──────┐
│ State      │  ← estados derivados, nunca fonte de verdade
└────────────┘
```

---

## Componentes

### Ledger
- Formato: NDJSON (append-only)
- Snapshots: escrita atômica (`latest.json`)
- Cadeia verificável via hash
- Regra explícita de gênese

### Ω-Gate (Governança)
- Ψ (coerência): métrica escalar
- CVaR95 (risco): cauda de perdas
- Decisão:
  - `ALLOW`
  - `QUARANTINE`
  - `REJECT`
- Falha de validação bloqueia escrita

### API
- FastAPI
- Autenticação Bearer Token
- Rate-limit por IP
- Endpoints:
  - `GET /health`
  - `GET /metrics`
  - `GET /blocks/{n}`
  - `POST /blocks`

### P2P
- TCP + NDJSON framing
- Handshake simples
- Base para gossip distribuído

---

## Instalação (Local)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

---

## Configuração

Gerar configuração inicial:

```bash
sudo ./bin/init-production.sh
```

Variáveis críticas:

* `MATVERSE_API_TOKEN` (obrigatório)
* `DATA_DIR`
* `LOG_DIR`

Sem token definido, **nenhuma escrita é permitida**.

---

## Execução

```bash
cassandra-matverse --config config/production/config.toml
```

Verificação:

```bash
curl http://localhost:8545/health
curl http://localhost:8545/metrics
```

---

## Deploy (Produção)

### systemd

```bash
sudo systemctl start cassandra-matverse
sudo journalctl -u cassandra-matverse -f
```

### Docker (mínimo)

```bash
docker-compose -f docker-compose.prod-minimal.yml up -d
```

---

## Segurança

* Execução como usuário não privilegiado
* Filesystem protegido (read-only onde possível)
* Token obrigatório para mutações
* Ledger nunca sobrescrito
* Snapshots atômicos

TLS deve ser fornecido por proxy externo (Nginx / Caddy).

---

## O que este sistema **não** faz

* Não promete “IA geral”
* Não usa consenso PoW/PoS
* Não tenta ser blockchain pública
* Não esconde heurísticas sob marketing

Ele **decide**, **registra** e **se limita**.

---

## Status

🟢 Produção mínima funcional  
🟡 Pronto para endurecimento  
🔵 Base para rede soberana MatVerse

---

## Licença

Defina conforme sua estratégia (MIT / Apache-2.0 / custom).
