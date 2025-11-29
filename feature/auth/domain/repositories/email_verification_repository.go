package repositories

import (
	"context"

	"zurvan-api/feature/auth/domain/models"

	"github.com/google/uuid"
)

// EmailVerificationRepository defines the interface for email verification data persistence
type EmailVerificationRepository interface {
	// Create creates a new email verification record
	Create(ctx context.Context, verification *models.EmailVerification) error

	// GetByUserID retrieves the latest email verification for a user
	GetByUserID(ctx context.Context, userID uuid.UUID) (*models.EmailVerification, error)

	// GetByEmailAndCode retrieves verification by email and code
	GetByEmailAndCode(ctx context.Context, email, code string) (*models.EmailVerification, error)

	// MarkAsUsed marks a verification code as used
	MarkAsUsed(ctx context.Context, id uuid.UUID) error

	// DeleteExpired deletes expired verification codes
	DeleteExpired(ctx context.Context) error

	// DeleteByUserID deletes all verification records for a user
	DeleteByUserID(ctx context.Context, userID uuid.UUID) error
}
