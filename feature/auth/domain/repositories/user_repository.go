package repositories

import (
	"context"

	"zurvan-api/feature/auth/domain/models"

	"github.com/google/uuid"
)

// UserRepository defines the interface for user data persistence
type UserRepository interface {
	// Create creates a new user
	Create(ctx context.Context, user *models.User) error

	// GetByID retrieves a user by their ID
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)

	// GetByEmail retrieves a user by their email
	GetByEmail(ctx context.Context, email string) (*models.User, error)

	// Update updates an existing user
	Update(ctx context.Context, user *models.User) error

	// UpdateVerificationStatus updates the user's email verification status
	UpdateVerificationStatus(ctx context.Context, userID uuid.UUID, isVerified bool) error

	// UpdateLastLoginAt updates the user's last login timestamp
	UpdateLastLoginAt(ctx context.Context, userID uuid.UUID) error

	// Delete deletes a user (soft delete)
	Delete(ctx context.Context, id uuid.UUID) error

	// EmailExists checks if an email already exists
	EmailExists(ctx context.Context, email string) (bool, error)
}
