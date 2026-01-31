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

---

## Desenvolvimento local

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Configure as variáveis de ambiente (exemplo):

```bash
export CAS_RUN_DATABASE_URL=postgresql://postgres:postgres@localhost:5432/cassandra_run
export CAS_RUN_TOKEN=seu_token_aqui
export CAS_RUN_PBSE_ENDPOINT=http://localhost:8001
```

Execute a API:

```bash
uvicorn cassandra_run.api:app --reload
```

---

## Docker

```bash
export CAS_RUN_TOKEN=seu_token_aqui
export CAS_RUN_PBSE_ENDPOINT=http://localhost:8001
docker-compose up --build
```

---

## CLI

```bash
export CAS_RUN_API_URL=http://localhost:8080
export CAS_RUN_TOKEN=seu_token_aqui

python cli.py submit --payload '{"key": "value"}'
python cli.py ledger
python cli.py proof --event-id 1
python cli.py replay
```

---

## Endpoints

- `POST /submit`
- `GET /ledger`
- `GET /proof/{event_id}`
- `POST /replay`

---

## PBSE

O runtime consulta o PBSE em `/evaluate`. Em caso de falha, o evento é bloqueado
por padrão (fail-closed).

Para desenvolvimento local, execute o mock do PBSE:

```bash
python mock_pbse.py
```

---

## Teste de carga (k6)

```bash
k6 run --env BASE_URL=http://localhost:8080 --env TOKEN=seu_token load_test.js
```
