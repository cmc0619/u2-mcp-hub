"""The settings database schema.

Timestamps are REAL seconds since the epoch, which compare and subtract without
parsing. Booleans are INTEGER 0/1. Secrets live only in *_enc columns, encrypted
by SecretBox; bearer secrets (OAuth codes, tokens, states) only as SHA-256 hashes.
"""

# Saved database notes. Scope hashes normalized server/account in both modes; the
# namespaces table keeps each scope's readable server/account.
KNOWLEDGE_SCHEMA = """
CREATE TABLE IF NOT EXISTS knowledge (
    scope TEXT NOT NULL,
    topic TEXT NOT NULL,
    topic_key TEXT NOT NULL,
    content TEXT NOT NULL,
    updated_at REAL NOT NULL,
    PRIMARY KEY (scope, topic_key)
);
CREATE TABLE IF NOT EXISTS knowledge_namespaces (
    scope TEXT PRIMARY KEY,
    server TEXT NOT NULL,
    account TEXT NOT NULL
);
"""

SCHEMA = (
    """
CREATE TABLE connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    service TEXT NOT NULL CHECK (service IN ('uvcs', 'udcs')),
    account TEXT NOT NULL,
    ssl INTEGER NOT NULL DEFAULT 0,
    login_mode TEXT NOT NULL CHECK (login_mode IN ('shared', 'per_user')),
    shared_user TEXT,
    shared_password_enc TEXT,
    read_only INTEGER NOT NULL DEFAULT 1,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at REAL NOT NULL,
    created_by TEXT,
    updated_at REAL NOT NULL,
    updated_by TEXT,
    -- optimistic locking: an edit names the version it started from
    version INTEGER NOT NULL DEFAULT 1
);

-- A company sign-in identity is the provider's issuer plus its subject.
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('sso', 'local')),
    username TEXT UNIQUE,
    sso_issuer TEXT,
    sso_subject TEXT,
    email TEXT,
    display_name TEXT,
    password_hash TEXT,
    is_admin INTEGER NOT NULL DEFAULT 0,
    disabled INTEGER NOT NULL DEFAULT 0,
    last_sso_login_at REAL,
    groups_unavailable INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL,
    -- set by `u2-mcp admin reset-password`
    must_change_password INTEGER NOT NULL DEFAULT 0,
    CHECK (
        (kind = 'sso' AND sso_subject IS NOT NULL)
        OR (kind = 'local' AND username IS NOT NULL)
    )
);

CREATE UNIQUE INDEX users_sso_identity ON users (sso_issuer, sso_subject);

-- A group belongs to the provider that named it, like a user (issuer + subject).
CREATE TABLE groups (
    id INTEGER PRIMARY KEY,
    issuer TEXT,
    external_id TEXT NOT NULL,
    label TEXT,
    first_seen_at REAL NOT NULL,
    last_seen_at REAL NOT NULL
);

CREATE UNIQUE INDEX groups_sso_identity ON groups (issuer, external_id);

CREATE TABLE user_groups (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    recorded_at REAL NOT NULL,
    PRIMARY KEY (user_id, group_id)
);

CREATE TABLE roles (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    builtin INTEGER NOT NULL DEFAULT 0,
    permissions TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE grants (
    id INTEGER PRIMARY KEY,
    connection_id INTEGER NOT NULL REFERENCES connections(id) ON DELETE CASCADE,
    subject_type TEXT NOT NULL CHECK (subject_type IN ('user', 'group', 'everyone')),
    subject_id INTEGER,
    role_id INTEGER NOT NULL REFERENCES roles(id),
    created_at REAL NOT NULL,
    CHECK ((subject_type = 'everyone') = (subject_id IS NULL))
);

CREATE UNIQUE INDEX grants_one_per_subject
    ON grants (connection_id, subject_type, COALESCE(subject_id, 0));

-- A person's own U2 login on a per-user connection, whatever grant gives access.
CREATE TABLE user_u2_logins (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    connection_id INTEGER NOT NULL REFERENCES connections(id) ON DELETE CASCADE,
    u2_user TEXT NOT NULL,
    u2_password_enc TEXT NOT NULL,
    updated_at REAL NOT NULL,
    PRIMARY KEY (user_id, connection_id)
);

-- Personal access tokens.
CREATE TABLE tokens (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    last_used_at REAL,
    last_used_ip TEXT,
    revoked_at REAL
);

-- Server-side admin sessions; only a hash of the session id is stored.
CREATE TABLE admin_sessions (
    id_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    created_at REAL NOT NULL,
    last_seen_at REAL NOT NULL,
    ip TEXT
);

CREATE INDEX admin_sessions_user ON admin_sessions (user_id);

CREATE TABLE audit (
    id INTEGER PRIMARY KEY,
    at REAL NOT NULL,
    actor_user_id INTEGER,
    actor_label TEXT,
    kind TEXT NOT NULL CHECK (kind IN ('tool', 'admin', 'auth')),
    connection_id INTEGER,
    action TEXT NOT NULL,
    params TEXT,
    outcome TEXT NOT NULL,
    duration_ms REAL
);

CREATE INDEX audit_at ON audit (at);

CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- The MCP OAuth bridge: registered clients, and codes, tokens and in-flight
-- sign-ins keyed by the hash of their secret value.
CREATE TABLE oauth_clients (
    client_id TEXT PRIMARY KEY,
    redirect_key TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE INDEX oauth_clients_redirect_key ON oauth_clients (redirect_key);

CREATE TABLE oauth_codes (
    code_hash TEXT PRIMARY KEY,
    expires_at REAL NOT NULL,
    payload TEXT NOT NULL
);

CREATE TABLE oauth_tokens (
    token_hash TEXT NOT NULL,
    token_type TEXT NOT NULL,
    client_id TEXT NOT NULL,
    expires_at REAL,
    payload TEXT NOT NULL,
    PRIMARY KEY (token_hash, token_type)
);

CREATE INDEX oauth_tokens_client ON oauth_tokens (client_id);

CREATE TABLE oauth_pending (
    state_hash TEXT PRIMARY KEY,
    expires_at REAL NOT NULL,
    payload TEXT NOT NULL
);
"""
    + KNOWLEDGE_SCHEMA
)
