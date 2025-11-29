-- Create email_verifications table
CREATE TABLE email_verifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    verification_code VARCHAR(6) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    is_used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for better performance
CREATE INDEX idx_email_verifications_user_id ON email_verifications(user_id);
CREATE INDEX idx_email_verifications_email_code ON email_verifications(email, verification_code);
CREATE INDEX idx_email_verifications_expires_at ON email_verifications(expires_at);
CREATE INDEX idx_email_verifications_is_used ON email_verifications(is_used);

-- Add comment for documentation
COMMENT ON TABLE email_verifications IS 'Email verification codes for user registration';
COMMENT ON COLUMN email_verifications.verification_code IS '6-digit verification code sent via email';
COMMENT ON COLUMN email_verifications.expires_at IS 'Expiration timestamp for the verification code';
COMMENT ON COLUMN email_verifications.is_used IS 'Whether the verification code has been used';