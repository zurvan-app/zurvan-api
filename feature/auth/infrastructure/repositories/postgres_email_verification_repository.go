package repositories

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"zurvan-api/feature/auth/domain/models"
	"zurvan-api/feature/auth/domain/repositories"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type postgresEmailVerificationRepository struct {
	db *pgxpool.Pool
}

// NewPostgresEmailVerificationRepository creates a new instance of PostgreSQL email verification repository
func NewPostgresEmailVerificationRepository(db *pgxpool.Pool) repositories.EmailVerificationRepository {
	return &postgresEmailVerificationRepository{
		db: db,
	}
}

func (r *postgresEmailVerificationRepository) Create(ctx context.Context, verification *models.EmailVerification) error {
	query := `
		INSERT INTO email_verifications (id, user_id, email, verification_code, expires_at, is_used, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	_, err := r.db.Exec(ctx, query,
		verification.ID,
		verification.UserID,
		verification.Email,
		verification.Code,
		verification.ExpiresAt,
		verification.IsUsed,
		verification.CreatedAt,
		verification.UpdatedAt,
	)

	return err
}

func (r *postgresEmailVerificationRepository) GetByUserID(ctx context.Context, userID uuid.UUID) (*models.EmailVerification, error) {
	query := `
		SELECT id, user_id, email, verification_code, expires_at, is_used, created_at, updated_at
		FROM email_verifications 
		WHERE user_id = $1 
		ORDER BY created_at DESC 
		LIMIT 1`

	verification := &models.EmailVerification{}
	err := r.db.QueryRow(ctx, query, userID).Scan(
		&verification.ID,
		&verification.UserID,
		&verification.Email,
		&verification.Code,
		&verification.ExpiresAt,
		&verification.IsUsed,
		&verification.CreatedAt,
		&verification.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("verification not found")
		}
		return nil, err
	}

	return verification, nil
}

func (r *postgresEmailVerificationRepository) GetByEmailAndCode(ctx context.Context, email, code string) (*models.EmailVerification, error) {
	query := `
		SELECT id, user_id, email, verification_code, expires_at, is_used, created_at, updated_at
		FROM email_verifications 
		WHERE email = $1 AND verification_code = $2 AND is_used = false AND expires_at > NOW()`

	verification := &models.EmailVerification{}
	err := r.db.QueryRow(ctx, query, email, code).Scan(
		&verification.ID,
		&verification.UserID,
		&verification.Email,
		&verification.Code,
		&verification.ExpiresAt,
		&verification.IsUsed,
		&verification.CreatedAt,
		&verification.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("invalid or expired verification code")
		}
		return nil, err
	}

	return verification, nil
}

func (r *postgresEmailVerificationRepository) MarkAsUsed(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE email_verifications 
		SET is_used = true, updated_at = $1
		WHERE id = $2`

	result, err := r.db.Exec(ctx, query, time.Now(), id)
	if err != nil {
		return err
	}

	rowsAffected := result.RowsAffected()

	if rowsAffected == 0 {
		return errors.New("verification not found")
	}

	return nil
}

func (r *postgresEmailVerificationRepository) DeleteExpired(ctx context.Context) error {
	query := `DELETE FROM email_verifications WHERE expires_at < NOW()`

	_, err := r.db.Exec(ctx, query)
	return err
}

func (r *postgresEmailVerificationRepository) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
	query := `DELETE FROM email_verifications WHERE user_id = $1`

	_, err := r.db.Exec(ctx, query, userID)
	return err
}
