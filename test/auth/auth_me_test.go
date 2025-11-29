package auth_test

import (
	"context"
	"testing"
	"time"

	"zurvan-api/feature/auth/application/usecases"
	"zurvan-api/feature/auth/domain/models"
	"zurvan-api/test/mocks"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
)

func TestAuthUseCase_GetUserFromToken(t *testing.T) {
	testUser := &models.User{
		ID:         uuid.New(),
		Name:       "Test User",
		Email:      "test@example.com",
		Password:   "hashedpassword",
		IsVerified: true,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	tests := []struct {
		name          string
		setupMocks    func(*mocks.MockUserRepository, *mocks.MockEmailVerificationRepository) string
		expectedError string
		shouldSucceed bool
	}{
		{
			name: "successful_token_validation",
			setupMocks: func(userRepo *mocks.MockUserRepository, emailRepo *mocks.MockEmailVerificationRepository) string {
				// First login to get a valid token
				hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("securepassword123"), bcrypt.DefaultCost)
				loginUser := &models.User{
					ID:         testUser.ID,
					Name:       testUser.Name,
					Email:      testUser.Email,
					Password:   string(hashedPassword),
					IsVerified: true,
					CreatedAt:  time.Now(),
					UpdatedAt:  time.Now(),
				}

				userRepo.On("GetByEmail", mock.Anything, testUser.Email).Return(loginUser, nil)
				userRepo.On("UpdateLastLoginAt", mock.Anything, testUser.ID).Return(nil)

				loginAuthUseCase := usecases.NewAuthUseCase(
					userRepo,
					emailRepo,
					[]byte("test-secret"),
					15*time.Minute,
					24*time.Hour,
				)

				loginInput := &models.LoginInput{
					Email:    testUser.Email,
					Password: "securepassword123",
				}

				authResponse, _ := loginAuthUseCase.Login(context.Background(), loginInput)

				// Reset mocks for the actual test
				userRepo.ExpectedCalls = nil
				emailRepo.ExpectedCalls = nil

				// Setup mock for GetUserFromToken
				userRepo.On("GetByID", mock.Anything, testUser.ID).Return(testUser, nil)

				return authResponse.AccessToken
			},
			shouldSucceed: true,
		},
		{
			name: "invalid_token_format",
			setupMocks: func(userRepo *mocks.MockUserRepository, emailRepo *mocks.MockEmailVerificationRepository) string {
				// No mocks needed for token validation errors
				return "invalid.token.format"
			},
			expectedError: "invalid token",
			shouldSucceed: false,
		},
		{
			name: "empty_token",
			setupMocks: func(userRepo *mocks.MockUserRepository, emailRepo *mocks.MockEmailVerificationRepository) string {
				// No mocks needed for token validation errors
				return ""
			},
			expectedError: "invalid token",
			shouldSucceed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			userRepo := new(mocks.MockUserRepository)
			emailRepo := new(mocks.MockEmailVerificationRepository)

			token := tt.setupMocks(userRepo, emailRepo)

			// Create use case
			authUseCase := usecases.NewAuthUseCase(
				userRepo,
				emailRepo,
				[]byte("test-secret"),
				15*time.Minute,
				24*time.Hour,
			)

			// Execute
			user, err := authUseCase.GetUserFromToken(context.Background(), token)

			// Assert
			if tt.shouldSucceed {
				assert.NoError(t, err)
				assert.NotNil(t, user)
				assert.Equal(t, testUser.Email, user.Email)
				assert.Equal(t, testUser.ID, user.ID)
				assert.Empty(t, user.Password) // Password should be hidden
			} else {
				assert.Error(t, err)
				assert.Nil(t, user)
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
