package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"zurvan-api/feature/auth/application/usecases"
	"zurvan-api/feature/auth/domain/models"
	"zurvan-api/test/mocks"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestAuthUseCase_VerifyEmail(t *testing.T) {
	testUserID := uuid.New()
	testUser := &models.User{
		ID:         testUserID,
		Name:       "Test User",
		Email:      "test@example.com",
		Password:   "hashedpassword",
		IsVerified: false,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	testVerification := &models.EmailVerification{
		ID:        uuid.New(),
		UserID:    testUserID,
		Email:     "test@example.com",
		Code:      "123456",
		ExpiresAt: time.Now().Add(15 * time.Minute),
		IsUsed:    false,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	tests := []struct {
		name          string
		userID        uuid.UUID
		input         *models.EmailVerificationInput
		setupMocks    func(*mocks.MockUserRepository, *mocks.MockEmailVerificationRepository)
		expectedError string
		shouldSucceed bool
	}{
		{
			name:   "successful_verification",
			userID: testUserID,
			input: &models.EmailVerificationInput{
				Code: "123456",
			},
			setupMocks: func(userRepo *mocks.MockUserRepository, emailRepo *mocks.MockEmailVerificationRepository) {
				userRepo.On("GetByID", mock.Anything, testUserID).Return(testUser, nil)
				emailRepo.On("GetByEmailAndCode", mock.Anything, "test@example.com", "123456").Return(testVerification, nil)
				emailRepo.On("MarkAsUsed", mock.Anything, testVerification.ID).Return(nil)
				userRepo.On("UpdateVerificationStatus", mock.Anything, testVerification.UserID, true).Return(nil)
			},
			shouldSucceed: true,
		},
		{
			name:   "invalid_code_format",
			userID: testUserID,
			input: &models.EmailVerificationInput{
				Code: "12345", // Should be 6 digits
			},
			setupMocks: func(userRepo *mocks.MockUserRepository, emailRepo *mocks.MockEmailVerificationRepository) {
				// No mocks needed for validation errors
			},
			expectedError: "validation error",
			shouldSucceed: false,
		},
		{
			name:   "user_not_found",
			userID: uuid.New(),
			input: &models.EmailVerificationInput{
				Code: "123456",
			},
			setupMocks: func(userRepo *mocks.MockUserRepository, emailRepo *mocks.MockEmailVerificationRepository) {
				userRepo.On("GetByID", mock.Anything, mock.AnythingOfType("uuid.UUID")).Return(nil, errors.New("user not found"))
			},
			expectedError: "user not found",
			shouldSucceed: false,
		},
		{
			name:   "verification_not_found",
			userID: testUserID,
			input: &models.EmailVerificationInput{
				Code: "999999",
			},
			setupMocks: func(userRepo *mocks.MockUserRepository, emailRepo *mocks.MockEmailVerificationRepository) {
				userRepo.On("GetByID", mock.Anything, testUserID).Return(testUser, nil)
				emailRepo.On("GetByEmailAndCode", mock.Anything, "test@example.com", "999999").Return(nil, errors.New("invalid or expired verification code"))
			},
			expectedError: "invalid or expired verification code",
			shouldSucceed: false,
		},
		{
			name:   "verification_belongs_to_different_user",
			userID: testUserID,
			input: &models.EmailVerificationInput{
				Code: "123456",
			},
			setupMocks: func(userRepo *mocks.MockUserRepository, emailRepo *mocks.MockEmailVerificationRepository) {
				differentUserVerification := &models.EmailVerification{
					ID:        uuid.New(),
					UserID:    uuid.New(), // Different user ID
					Email:     "test@example.com",
					Code:      "123456",
					ExpiresAt: time.Now().Add(15 * time.Minute),
					IsUsed:    false,
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}
				userRepo.On("GetByID", mock.Anything, testUserID).Return(testUser, nil)
				emailRepo.On("GetByEmailAndCode", mock.Anything, "test@example.com", "123456").Return(differentUserVerification, nil)
			},
			expectedError: "verification code not found",
			shouldSucceed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			userRepo := new(mocks.MockUserRepository)
			emailRepo := new(mocks.MockEmailVerificationRepository)

			tt.setupMocks(userRepo, emailRepo)

			// Create use case
			authUseCase := usecases.NewAuthUseCase(
				userRepo,
				emailRepo,
				[]byte("test-secret"),
				15*time.Minute,
				24*time.Hour,
			)

			// Execute
			err := authUseCase.VerifyEmail(context.Background(), tt.userID, tt.input)

			// Assert
			if tt.shouldSucceed {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				if tt.expectedError != "" {
					assert.Contains(t, err.Error(), tt.expectedError)
				}
			}

			// Verify mock expectations
			userRepo.AssertExpectations(t)
			emailRepo.AssertExpectations(t)
		})
	}
}

func TestAuthUseCase_RefreshToken(t *testing.T) {
	tests := []struct {
		name          string
		refreshToken  string
		setupMocks    func(*mocks.MockUserRepository, *mocks.MockEmailVerificationRepository)
		expectedError string
		shouldSucceed bool
	}{
		{
			name:         "invalid_token_format",
			refreshToken: "invalid.token.format",
			setupMocks: func(userRepo *mocks.MockUserRepository, emailRepo *mocks.MockEmailVerificationRepository) {
				// No mocks needed for token validation errors
			},
			expectedError: "invalid refresh token",
			shouldSucceed: false,
		},
		{
			name:         "empty_token",
			refreshToken: "",
			setupMocks: func(userRepo *mocks.MockUserRepository, emailRepo *mocks.MockEmailVerificationRepository) {
				// No mocks needed for token validation errors
			},
			expectedError: "invalid refresh token",
			shouldSucceed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			userRepo := new(mocks.MockUserRepository)
			emailRepo := new(mocks.MockEmailVerificationRepository)

			tt.setupMocks(userRepo, emailRepo)

			// Create use case
			authUseCase := usecases.NewAuthUseCase(
				userRepo,
				emailRepo,
				[]byte("test-secret"),
				15*time.Minute,
				24*time.Hour,
			)

			// Execute
			result, err := authUseCase.RefreshToken(context.Background(), tt.refreshToken)

			// Assert
			if tt.shouldSucceed {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.NotEmpty(t, result.AccessToken)
				assert.NotEmpty(t, result.RefreshToken)
				assert.Equal(t, int64(900), result.ExpiresIn)
				assert.NotNil(t, result.User)
				assert.Empty(t, result.User.Password)
			} else {
				assert.Error(t, err)
				assert.Nil(t, result)
				if tt.expectedError != "" {
					assert.Contains(t, err.Error(), tt.expectedError)
				}
			}

			// Verify mock expectations
			userRepo.AssertExpectations(t)
			emailRepo.AssertExpectations(t)
		})
	}
}

func TestAuthUseCase_ResendVerificationCode(t *testing.T) {
	testUserID := uuid.New()
	testUser := &models.User{
		ID:         testUserID,
		Name:       "Test User",
		Email:      "test@example.com",
		Password:   "hashedpassword",
		IsVerified: false,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	verifiedUserID := uuid.New()
	verifiedUser := &models.User{
		ID:         verifiedUserID,
		Name:       "Verified User",
		Email:      "verified@example.com",
		Password:   "hashedpassword",
		IsVerified: true,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	tests := []struct {
		name          string
		userID        uuid.UUID
		input         *models.ResendVerificationInput
		setupMocks    func(*mocks.MockUserRepository, *mocks.MockEmailVerificationRepository)
		expectedError string
		shouldSucceed bool
	}{
		{
			name:   "successful_resend",
			userID: testUserID,
			input:  &models.ResendVerificationInput{},
			setupMocks: func(userRepo *mocks.MockUserRepository, emailRepo *mocks.MockEmailVerificationRepository) {
				userRepo.On("GetByID", mock.Anything, testUserID).Return(testUser, nil)
				emailRepo.On("Create", mock.Anything, mock.AnythingOfType("*models.EmailVerification")).Return(nil)
			},
			shouldSucceed: true,
		},
		{
			name:   "user_not_found",
			userID: uuid.New(),
			input:  &models.ResendVerificationInput{},
			setupMocks: func(userRepo *mocks.MockUserRepository, emailRepo *mocks.MockEmailVerificationRepository) {
				userRepo.On("GetByID", mock.Anything, mock.AnythingOfType("uuid.UUID")).Return(nil, errors.New("user not found"))
			},
			expectedError: "user not found",
			shouldSucceed: false,
		},
		{
			name:   "already_verified",
			userID: verifiedUserID,
			input:  &models.ResendVerificationInput{},
			setupMocks: func(userRepo *mocks.MockUserRepository, emailRepo *mocks.MockEmailVerificationRepository) {
				userRepo.On("GetByID", mock.Anything, verifiedUserID).Return(verifiedUser, nil)
			},
			expectedError: "email already verified",
			shouldSucceed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			userRepo := new(mocks.MockUserRepository)
			emailRepo := new(mocks.MockEmailVerificationRepository)

			tt.setupMocks(userRepo, emailRepo)

			// Create use case
			authUseCase := usecases.NewAuthUseCase(
				userRepo,
				emailRepo,
				[]byte("test-secret"),
				15*time.Minute,
				24*time.Hour,
			)

			// Execute
			err := authUseCase.ResendVerificationCode(context.Background(), tt.userID, tt.input)

			// Assert
			if tt.shouldSucceed {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				if tt.expectedError != "" {
					assert.Contains(t, err.Error(), tt.expectedError)
				}
			}

			// Verify mock expectations
			userRepo.AssertExpectations(t)
			emailRepo.AssertExpectations(t)
		})
	}
}
