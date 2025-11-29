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
	"golang.org/x/crypto/bcrypt"
)

func TestAuthUseCase_Register(t *testing.T) {
	tests := []struct {
		name          string
		input         *models.UserInput
		setupMocks    func(*mocks.MockUserRepository, *mocks.MockEmailVerificationRepository)
		expectedError string
		shouldSucceed bool
	}{
		{
			name: "successful_registration",
			input: &models.UserInput{
				Name:     "John Doe",
				Email:    "test@example.com",
				Password: "securepassword123",
			},
			setupMocks: func(userRepo *mocks.MockUserRepository, emailRepo *mocks.MockEmailVerificationRepository) {
				userRepo.On("EmailExists", mock.Anything, "test@example.com").Return(false, nil)
				userRepo.On("Create", mock.Anything, mock.AnythingOfType("*models.User")).Return(nil)
				emailRepo.On("Create", mock.Anything, mock.AnythingOfType("*models.EmailVerification")).Return(nil)
			},
			shouldSucceed: true,
		},
		{
			name: "missing_name_field",
			input: &models.UserInput{
				Email:    "test@example.com",
				Password: "securepassword123",
			},
			setupMocks: func(userRepo *mocks.MockUserRepository, emailRepo *mocks.MockEmailVerificationRepository) {
				// No mocks needed for validation errors
			},
			expectedError: "validation error",
			shouldSucceed: false,
		},
		{
			name: "invalid_email_format",
			input: &models.UserInput{
				Name:     "John Doe",
				Email:    "invalid-email",
				Password: "securepassword123",
			},
			setupMocks: func(userRepo *mocks.MockUserRepository, emailRepo *mocks.MockEmailVerificationRepository) {
				// No mocks needed for validation errors
			},
			expectedError: "validation error",
			shouldSucceed: false,
		},
		{
			name: "password_too_short",
			input: &models.UserInput{
				Name:     "John Doe",
				Email:    "test@example.com",
				Password: "123",
			},
			setupMocks: func(userRepo *mocks.MockUserRepository, emailRepo *mocks.MockEmailVerificationRepository) {
				// No mocks needed for validation errors
			},
			expectedError: "validation error",
			shouldSucceed: false,
		},
		{
			name: "email_already_exists",
			input: &models.UserInput{
				Name:     "John Doe",
				Email:    "existing@example.com",
				Password: "securepassword123",
			},
			setupMocks: func(userRepo *mocks.MockUserRepository, emailRepo *mocks.MockEmailVerificationRepository) {
				userRepo.On("EmailExists", mock.Anything, "existing@example.com").Return(true, nil)
			},
			expectedError: "email already exists",
			shouldSucceed: false,
		},
		{
			name: "database_error_on_email_check",
			input: &models.UserInput{
				Name:     "John Doe",
				Email:    "test@example.com",
				Password: "securepassword123",
			},
			setupMocks: func(userRepo *mocks.MockUserRepository, emailRepo *mocks.MockEmailVerificationRepository) {
				userRepo.On("EmailExists", mock.Anything, "test@example.com").Return(false, errors.New("database error"))
			},
			expectedError: "failed to check email existence",
			shouldSucceed: false,
		},
		{
			name: "database_error_on_user_creation",
			input: &models.UserInput{
				Name:     "John Doe",
				Email:    "test@example.com",
				Password: "securepassword123",
			},
			setupMocks: func(userRepo *mocks.MockUserRepository, emailRepo *mocks.MockEmailVerificationRepository) {
				userRepo.On("EmailExists", mock.Anything, "test@example.com").Return(false, nil)
				userRepo.On("Create", mock.Anything, mock.AnythingOfType("*models.User")).Return(errors.New("database error"))
			},
			expectedError: "failed to create user",
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
			authResponse, err := authUseCase.Register(context.Background(), tt.input)

			// Assert
			if tt.shouldSucceed {
				assert.NoError(t, err)
				assert.NotNil(t, authResponse)
				assert.NotEmpty(t, authResponse.AccessToken)
				assert.NotEmpty(t, authResponse.RefreshToken)
				assert.True(t, authResponse.ExpiresIn > 0)
				assert.NotNil(t, authResponse.User)
				assert.Equal(t, tt.input.Name, authResponse.User.Name)
				assert.Equal(t, tt.input.Email, authResponse.User.Email)
				assert.False(t, authResponse.User.IsVerified) // Should be false initially
				assert.Empty(t, authResponse.User.Password)   // Password should be hidden
			} else {
				assert.Error(t, err)
				assert.Nil(t, authResponse)
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

func TestAuthUseCase_Login(t *testing.T) {
	tests := []struct {
		name          string
		input         *models.LoginInput
		setupMocks    func(*mocks.MockUserRepository, *mocks.MockEmailVerificationRepository)
		expectedError string
		shouldSucceed bool
	}{
		{
			name: "successful_login",
			input: &models.LoginInput{
				Email:    "test@example.com",
				Password: "securepassword123",
			},
			setupMocks: func(userRepo *mocks.MockUserRepository, emailRepo *mocks.MockEmailVerificationRepository) {
				// Create fresh test user for this specific test
				hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("securepassword123"), bcrypt.DefaultCost)
				testUser := &models.User{
					ID:         uuid.New(),
					Name:       "John Doe",
					Email:      "test@example.com",
					Password:   string(hashedPassword),
					IsVerified: true,
					CreatedAt:  time.Now(),
					UpdatedAt:  time.Now(),
				}
				userRepo.On("GetByEmail", mock.Anything, "test@example.com").Return(testUser, nil)
				userRepo.On("UpdateLastLoginAt", mock.Anything, testUser.ID).Return(nil)
			},
			shouldSucceed: true,
		},
		{
			name: "invalid_email_format",
			input: &models.LoginInput{
				Email:    "invalid-email",
				Password: "securepassword123",
			},
			setupMocks: func(userRepo *mocks.MockUserRepository, emailRepo *mocks.MockEmailVerificationRepository) {
				// No mocks needed for validation errors
			},
			expectedError: "validation error",
			shouldSucceed: false,
		},
		{
			name: "user_not_found",
			input: &models.LoginInput{
				Email:    "notfound@example.com",
				Password: "securepassword123",
			},
			setupMocks: func(userRepo *mocks.MockUserRepository, emailRepo *mocks.MockEmailVerificationRepository) {
				userRepo.On("GetByEmail", mock.Anything, "notfound@example.com").Return(nil, errors.New("user not found"))
			},
			expectedError: "invalid email or password",
			shouldSucceed: false,
		},
		{
			name: "wrong_password",
			input: &models.LoginInput{
				Email:    "test2@example.com",
				Password: "wrongpassword",
			},
			setupMocks: func(userRepo *mocks.MockUserRepository, emailRepo *mocks.MockEmailVerificationRepository) {
				// Create user with correct password hash
				hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("correctpassword"), bcrypt.DefaultCost)
				testUser := &models.User{
					ID:         uuid.New(),
					Name:       "Jane Doe",
					Email:      "test2@example.com",
					Password:   string(hashedPassword),
					IsVerified: true,
					CreatedAt:  time.Now(),
					UpdatedAt:  time.Now(),
				}
				userRepo.On("GetByEmail", mock.Anything, "test2@example.com").Return(testUser, nil)
			},
			expectedError: "invalid email or password",
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
			result, err := authUseCase.Login(context.Background(), tt.input)

			// Assert
			if tt.shouldSucceed {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.NotEmpty(t, result.AccessToken)
				assert.NotEmpty(t, result.RefreshToken)
				assert.Equal(t, int64(900), result.ExpiresIn) // 15 minutes in seconds
				assert.NotNil(t, result.User)
				assert.Equal(t, tt.input.Email, result.User.Email)
				assert.Empty(t, result.User.Password) // Password should be hidden
			} else {
				assert.Error(t, err)
				assert.Nil(t, result)
				if tt.expectedError != "" {
					if !assert.Contains(t, err.Error(), tt.expectedError) {
						t.Logf("Expected error to contain '%s', but got '%s'", tt.expectedError, err.Error())
					}
				}
			}

			// Verify mock expectations
			userRepo.AssertExpectations(t)
			emailRepo.AssertExpectations(t)
		})
	}
}
