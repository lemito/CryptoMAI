CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(50) UNIQUE NOT NULL CHECK (LENGTH(username) >= 3),
    password_hash VARCHAR(128) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_username ON users(username);

CREATE TABLE user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(64) UNIQUE NOT NULL, 
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    is_active BOOLEAN DEFAULT true
);

CREATE INDEX idx_sessions_token ON user_sessions(session_token) WHERE is_active = true;
CREATE INDEX idx_sessions_expiry ON user_sessions(expires_at) WHERE is_active = true;

CREATE OR REPLACE FUNCTION update_modified_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_users_modtime
BEFORE UPDATE ON users
FOR EACH ROW EXECUTE FUNCTION update_modified_column();