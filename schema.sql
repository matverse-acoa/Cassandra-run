-- Criação do banco de dados e tabelas para o Cassandra-run

CREATE TABLE events (
    id SERIAL PRIMARY KEY,
    prev_hash TEXT NOT NULL,
    data_hash TEXT NOT NULL,
    merkle_root TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status TEXT NOT NULL DEFAULT 'PENDING',
    payload JSONB NOT NULL,
    pbse_decision TEXT NOT NULL DEFAULT 'BLOCK'
);

CREATE TABLE proofs (
    id SERIAL PRIMARY KEY,
    event_id INTEGER NOT NULL REFERENCES events(id),
    signer TEXT NOT NULL,
    signature TEXT NOT NULL,
    signed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_events_data_hash ON events (data_hash);
CREATE INDEX idx_proofs_event_id ON proofs (event_id);
