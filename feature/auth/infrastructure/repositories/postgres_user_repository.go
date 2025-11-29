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
	"github.com/lib/pq"
)

type postgresUserRepository struct {
	db *pgxpool.Pool
}

// NewPostgresUserRepository creates a new instance of PostgreSQL user repository
func NewPostgresUserRepository(db *pgxpool.Pool) repositories.UserRepository {
	return &postgresUserRepository{
		db: db,
	}
}

func (r *postgresUserRepository) Create(ctx context.Context, user *models.User) error {
	query := `
		INSERT INTO users (id, name, email, password_hash, is_verified, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err := r.db.Exec(ctx, query,
		user.ID,
		user.Name,
		user.Email,
		user.Password,
		user.IsVerified,
		user.CreatedAt,
		user.UpdatedAt,
	)

	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok {
			if pqErr.Code == "23505" { // unique violation
				return errors.New("email already exists")
			}
		}
		return err
	}

	return nil
}

func (r *postgresUserRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	query := `
		SELECT id, name, email, password_hash, is_verified, created_at, updated_at, last_login_at
		FROM users 
		WHERE id = $1`

	user := &models.User{}
	err := r.db.QueryRow(ctx, query, id).Scan(
		&user.ID,
		&user.Name,
		&user.Email,
		&user.Password,
		&user.IsVerified,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.LastLoginAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("user not found")
		}
		return nil, err
	}

	return user, nil
}

func (r *postgresUserRepository) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	query := `
		SELECT id, name, email, password_hash, is_verified, created_at, updated_at, last_login_at
		FROM users 
		WHERE email = $1`

	user := &models.User{}
	err := r.db.QueryRow(ctx, query, email).Scan(
		&user.ID,
		&user.Name,
		&user.Email,
		&user.Password,
		&user.IsVerified,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.LastLoginAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("user not found")
		}
		return nil, err
	}

	return user, nil
}

func (r *postgresUserRepository) Update(ctx context.Context, user *models.User) error {
	query := `
		UPDATE users 
		SET email = $1, password_hash = $2, is_verified = $3, updated_at = $4
		WHERE id = $5`

	result, err := r.db.Exec(ctx, query,
		user.Email,
		user.Password,
		user.IsVerified,
		time.Now(),
		user.ID,
	)

	if err != nil {
		return err
	}

	rowsAffected := result.RowsAffected()

	if rowsAffected == 0 {
		return errors.New("user not found")
	}

	return nil
}

func (r *postgresUserRepository) UpdateVerificationStatus(ctx context.Context, userID uuid.UUID, isVerified bool) error {
	query := `
		UPDATE users 
		SET is_verified = $1, updated_at = $2
		WHERE id = $3`

	result, err := r.db.Exec(ctx, query, isVerified, time.Now(), userID)
	if err != nil {
		return err
	}

	rowsAffected := result.RowsAffected()

	if rowsAffected == 0 {
		return errors.New("user not found")
	}

	return nil
}

func (r *postgresUserRepository) UpdateLastLoginAt(ctx context.Context, userID uuid.UUID) error {
	query := `
		UPDATE users 
		SET last_login_at = $1, updated_at = $2
		WHERE id = $3`

	now := time.Now()
	result, err := r.db.Exec(ctx, query, now, now, userID)
	if err != nil {
		return err
	}

	rowsAffected := result.RowsAffected()

	if rowsAffected == 0 {
		return errors.New("user not found")
	}

	return nil
}

func (r *postgresUserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM users WHERE id = $1`

	result, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return err
	}

	rowsAffected := result.RowsAffected()

	if rowsAffected == 0 {
		return errors.New("user not found")
	}

	return nil
}

func (r *postgresUserRepository) EmailExists(ctx context.Context, email string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)`

	var exists bool
	err := r.db.QueryRow(ctx, query, email).Scan(&exists)
	if err != nil {
		return false, err
	}

	return exists, nil
}
