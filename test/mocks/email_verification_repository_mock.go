package mocks

import (
	"context"

	"zurvan-api/feature/auth/domain/models"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
)

// MockEmailVerificationRepository is a mock implementation of the EmailVerificationRepository interface
type MockEmailVerificationRepository struct {
	mock.Mock
}

func (m *MockEmailVerificationRepository) Create(ctx context.Context, verification *models.EmailVerification) error {
	args := m.Called(ctx, verification)
	return args.Error(0)
}

func (m *MockEmailVerificationRepository) GetByUserID(ctx context.Context, userID uuid.UUID) (*models.EmailVerification, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.EmailVerification), args.Error(1)
}

func (m *MockEmailVerificationRepository) GetByEmailAndCode(ctx context.Context, email, code string) (*models.EmailVerification, error) {
	args := m.Called(ctx, email, code)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.EmailVerification), args.Error(1)
}

func (m *MockEmailVerificationRepository) MarkAsUsed(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockEmailVerificationRepository) DeleteExpired(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockEmailVerificationRepository) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}
