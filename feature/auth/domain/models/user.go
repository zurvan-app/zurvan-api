package models

import (
	"time"

	"github.com/google/uuid"
)

// User represents the user entity in our domain
type User struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	Name        string     `json:"name" db:"name" validate:"required,min=2,max=50"`
	Email       string     `json:"email" db:"email" validate:"required,email"`
	Password    string     `json:"-" db:"password_hash" validate:"required,min=8"`
	IsVerified  bool       `json:"is_verified" db:"is_verified"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at" db:"updated_at"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty" db:"last_login_at"`
}

// UserInput represents the input for user registration
type UserInput struct {
	Name     string `json:"name" validate:"required,min=2,max=50"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8,max=128"`
}

// LoginInput represents the input for user login
type LoginInput struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// AuthResponse represents the response after successful authentication
type AuthResponse struct {
	User         *User  `json:"user"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

// TokenClaims represents the JWT token claims
type TokenClaims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Type   string `json:"type"` // "access" or "refresh"
}
