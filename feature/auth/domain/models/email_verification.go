package models

import (
	"time"

	"github.com/google/uuid"
)

// EmailVerification represents the email verification entity
type EmailVerification struct {
	ID        uuid.UUID `json:"id" db:"id"`
	UserID    uuid.UUID `json:"user_id" db:"user_id"`
	Email     string    `json:"email" db:"email"`
	Code      string    `json:"code" db:"verification_code"`
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`
	IsUsed    bool      `json:"is_used" db:"is_used"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// EmailVerificationInput represents input for email verification
type EmailVerificationInput struct {
	Code string `json:"code" validate:"required,len=6"`
}

// ResendVerificationInput represents input for resending verification code
type ResendVerificationInput struct {
	// No fields needed - will use authenticated user's email
}
