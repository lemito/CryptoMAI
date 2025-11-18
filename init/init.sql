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

CREATE TABLE contacts (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    contact_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status VARCHAR(20) NOT NULL CHECK (status IN ('pending', 'accepted', 'rejected')),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (user_id, contact_id),
    CONSTRAINT no_self_contact CHECK (user_id != contact_id)
);

CREATE INDEX idx_contacts_user_id ON contacts(user_id);
CREATE INDEX idx_contacts_contact_id ON contacts(contact_id);
CREATE INDEX idx_contacts_status ON contacts(status);
CREATE INDEX idx_contacts_pending ON contacts(status) WHERE status = 'pending';


CREATE TABLE IF NOT EXISTS chats (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    initiator_username VARCHAR(50) NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    participant_username VARCHAR(50) NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    algorithm VARCHAR(20) NOT NULL,
    mode VARCHAR(20) NOT NULL,
    padding VARCHAR(20) NOT NULL,
    base_iv BYTEA NOT NULL,
    initiator_dh_params JSONB NOT NULL,
    peer_dh_params JSONB,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CHECK (initiator_username != participant_username)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_chats_unique_active 
ON chats(initiator_username, participant_username) 
WHERE is_active = true;

CREATE TABLE IF NOT EXISTS user_chats (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    chat_id UUID NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
    username VARCHAR(50) NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    is_active BOOLEAN DEFAULT true,
    joined_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    left_at TIMESTAMP WITH TIME ZONE,
    
    PRIMARY KEY (user_id, chat_id)
);

CREATE INDEX IF NOT EXISTS idx_chats_initiator ON chats(initiator_username);
CREATE INDEX IF NOT EXISTS idx_chats_participant ON chats(participant_username);
CREATE INDEX IF NOT EXISTS idx_chats_active ON chats(is_active) WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_user_chats_username ON user_chats(username);
CREATE INDEX IF NOT EXISTS idx_user_chats_active ON user_chats(is_active) WHERE is_active = true;