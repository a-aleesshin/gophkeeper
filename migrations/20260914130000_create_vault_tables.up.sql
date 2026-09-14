CREATE TABLE secrets (
    id uuid PRIMARY KEY,
    owner_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type varchar(16) NOT NULL CHECK (type IN ('credentials', 'text', 'binary', 'card')),
    payload bytea NOT NULL,
    metadata bytea NOT NULL,
    version bigint NOT NULL CHECK (version > 0),
    deleted boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK (octet_length(payload) <= 1048576),
    CHECK (octet_length(metadata) <= 16384),
    CHECK (deleted OR octet_length(payload) > 0)
);

CREATE INDEX secrets_owner_updated_idx ON secrets (owner_id, updated_at);
