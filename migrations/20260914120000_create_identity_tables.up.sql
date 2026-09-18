CREATE TABLE users (
    id uuid PRIMARY KEY,
    login varchar(64) NOT NULL UNIQUE,
    password_hash bytea NOT NULL,
    created_at timestamptz NOT NULL
);
