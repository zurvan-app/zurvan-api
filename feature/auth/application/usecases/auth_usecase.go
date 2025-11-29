package usecases

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"math/big"
	"time"

	"zurvan-api/feature/auth/domain/models"
	"zurvan-api/feature/auth/domain/repositories"

	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// AuthUseCase handles authentication-related business logic
type AuthUseCase struct {
	userRepo              repositories.UserRepository
	emailVerificationRepo repositories.EmailVerificationRepository
	validator             *validator.Validate
	jwtSecret             []byte
	accessTokenTTL        time.Duration
	refreshTokenTTL       time.Duration
}

// NewAuthUseCase creates a new instance of AuthUseCase
func NewAuthUseCase(
	userRepo repositories.UserRepository,
	emailVerificationRepo repositories.EmailVerificationRepository,
	jwtSecret []byte,
	accessTokenTTL, refreshTokenTTL time.Duration,
) *AuthUseCase {
	return &AuthUseCase{
		userRepo:              userRepo,
		emailVerificationRepo: emailVerificationRepo,
		validator:             validator.New(),
		jwtSecret:             jwtSecret,
		accessTokenTTL:        accessTokenTTL,
		refreshTokenTTL:       refreshTokenTTL,
	}
}

// Register creates a new user account and sends email verification
func (uc *AuthUseCase) Register(ctx context.Context, input *models.UserInput) (*models.AuthResponse, error) {
	// Validate input
	if err := uc.validator.Struct(input); err != nil {
		return nil, fmt.Errorf("validation error: %w", err)
	}

	// Check if email already exists
	exists, err := uc.userRepo.EmailExists(ctx, input.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to check email existence: %w", err)
	}
	if exists {
		return nil, errors.New("email already exists")
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user
	user := &models.User{
		ID:         uuid.New(),
		Name:       input.Name,
		Email:      input.Email,
		Password:   string(hashedPassword),
		IsVerified: false,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	if err := uc.userRepo.Create(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Generate and send verification code
	if err := uc.generateAndSaveVerificationCode(ctx, user.ID, user.Email); err != nil {
		return nil, fmt.Errorf("failed to generate verification code: %w", err)
	}

	// Generate tokens for immediate login after registration
	accessToken, err := uc.generateToken(user, "access", uc.accessTokenTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := uc.generateToken(user, "refresh", uc.refreshTokenTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Hide password in response
	user.Password = ""

	return &models.AuthResponse{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(uc.accessTokenTTL.Seconds()),
	}, nil
}

// Login authenticates a user and returns tokens
func (uc *AuthUseCase) Login(ctx context.Context, input *models.LoginInput) (*models.AuthResponse, error) {
	// Validate input
	if err := uc.validator.Struct(input); err != nil {
		return nil, fmt.Errorf("validation error: %w", err)
	}

	// Get user by email
	user, err := uc.userRepo.GetByEmail(ctx, input.Email)
	if err != nil {
		return nil, errors.New("invalid email or password")
	}

	// Check password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil {
		return nil, errors.New("invalid email or password")
	}

	// Update last login
	if err := uc.userRepo.UpdateLastLoginAt(ctx, user.ID); err != nil {
		// Log error but don't fail login
		log.Printf("failed to update last login: %v", err)
	}

	// Generate tokens
	accessToken, err := uc.generateToken(user, "access", uc.accessTokenTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := uc.generateToken(user, "refresh", uc.refreshTokenTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Hide password in response
	user.Password = ""

	return &models.AuthResponse{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(uc.accessTokenTTL.Seconds()),
	}, nil
}

// VerifyEmail verifies a user's email using the verification code (requires authentication)
func (uc *AuthUseCase) VerifyEmail(ctx context.Context, userID uuid.UUID, input *models.EmailVerificationInput) error {
	// Validate input
	if err := uc.validator.Struct(input); err != nil {
		return fmt.Errorf("validation error: %w", err)
	}

	// Get user to find their email
	user, err := uc.userRepo.GetByID(ctx, userID)
	if err != nil {
		return errors.New("user not found")
	}

	// Get verification by email and code
	verification, err := uc.emailVerificationRepo.GetByEmailAndCode(ctx, user.Email, input.Code)
	if err != nil {
		return err // Error message already set in repository
	}

	// Ensure the verification belongs to the authenticated user
	if verification.UserID != userID {
		return errors.New("verification code not found")
	}

	// Mark verification as used
	if err := uc.emailVerificationRepo.MarkAsUsed(ctx, verification.ID); err != nil {
		return fmt.Errorf("failed to mark verification as used: %w", err)
	}

	// Update user verification status
	if err := uc.userRepo.UpdateVerificationStatus(ctx, verification.UserID, true); err != nil {
		return fmt.Errorf("failed to update user verification status: %w", err)
	}

	return nil
}

// ResendVerificationCode generates and sends a new verification code (requires authentication)
func (uc *AuthUseCase) ResendVerificationCode(ctx context.Context, userID uuid.UUID, input *models.ResendVerificationInput) error {
	// Validate input
	if err := uc.validator.Struct(input); err != nil {
		return fmt.Errorf("validation error: %w", err)
	}

	// Get user by ID
	user, err := uc.userRepo.GetByID(ctx, userID)
	if err != nil {
		return errors.New("user not found")
	}

	// Check if user is already verified
	if user.IsVerified {
		return errors.New("email already verified")
	}

	// Generate and send new verification code
	if err := uc.generateAndSaveVerificationCode(ctx, user.ID, user.Email); err != nil {
		return fmt.Errorf("failed to generate verification code: %w", err)
	}

	return nil
}

// RefreshToken generates new access token using refresh token
func (uc *AuthUseCase) RefreshToken(ctx context.Context, refreshToken string) (*models.AuthResponse, error) {
	// Validate and parse refresh token
	claims, err := uc.validateToken(refreshToken)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}

	if claims.Type != "refresh" {
		return nil, errors.New("invalid token type")
	}

	// Get user
	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		return nil, errors.New("invalid user ID in token")
	}

	user, err := uc.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, errors.New("user not found")
	}

	// Generate new access token
	accessToken, err := uc.generateToken(user, "access", uc.accessTokenTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate new refresh token
	newRefreshToken, err := uc.generateToken(user, "refresh", uc.refreshTokenTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Hide password in response
	user.Password = ""

	return &models.AuthResponse{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    int64(uc.accessTokenTTL.Seconds()),
	}, nil
}

// generateVerificationCode generates a 6-digit verification code
func (uc *AuthUseCase) generateVerificationCode() (string, error) {
	const digits = "0123456789"
	code := make([]byte, 6)

	for i := 0; i < 6; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		if err != nil {
			return "", err
		}
		code[i] = digits[num.Int64()]
	}

	return string(code), nil
}

// generateAndSaveVerificationCode generates and saves a verification code
func (uc *AuthUseCase) generateAndSaveVerificationCode(ctx context.Context, userID uuid.UUID, email string) error {
	// Generate verification code
	code, err := uc.generateVerificationCode()
	if err != nil {
		return err
	}

	// Create verification record
	verification := &models.EmailVerification{
		ID:        uuid.New(),
		UserID:    userID,
		Email:     email,
		Code:      code,
		ExpiresAt: time.Now().Add(15 * time.Minute), // 15 minutes expiry
		IsUsed:    false,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Save to database
	if err := uc.emailVerificationRepo.Create(ctx, verification); err != nil {
		return err
	}

	// TODO: Send email with verification code
	// For now, we'll just log it (in production, integrate with email service)
	log.Printf("Verification code for %s: %s", email, code)

	return nil
}

// generateToken generates a JWT token
func (uc *AuthUseCase) generateToken(user *models.User, tokenType string, ttl time.Duration) (string, error) {
	claims := jwt.MapClaims{
		"user_id": user.ID.String(),
		"email":   user.Email,
		"type":    tokenType,
		"exp":     time.Now().Add(ttl).Unix(),
		"iat":     time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(uc.jwtSecret)
}

// validateToken validates and parses a JWT token
func (uc *AuthUseCase) validateToken(tokenString string) (*models.TokenClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return uc.jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	userID, ok := claims["user_id"].(string)
	if !ok {
		return nil, errors.New("invalid user ID in token")
	}

	email, ok := claims["email"].(string)
	if !ok {
		return nil, errors.New("invalid email in token")
	}

	tokenType, ok := claims["type"].(string)
	if !ok {
		return nil, errors.New("invalid token type in token")
	}

	return &models.TokenClaims{
		UserID: userID,
		Email:  email,
		Type:   tokenType,
	}, nil
}

// GetUserFromToken validates a JWT token and returns the user information
func (uc *AuthUseCase) GetUserFromToken(ctx context.Context, tokenString string) (*models.User, error) {
	// Validate the token
	claims, err := uc.validateToken(tokenString)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	// Check if it's an access token
	if claims.Type != "access" {
		return nil, errors.New("invalid token type, access token required")
	}

	// Parse user ID
	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID in token: %w", err)
	}

	// Get user from repository
	user, err := uc.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Hide password in response
	user.Password = ""

	return user, nil
}
