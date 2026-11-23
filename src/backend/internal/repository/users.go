package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/roomies/backend/internal/models"
)

// ErrEmailInUse means the email already belongs to a different sign-in subject.
var ErrEmailInUse = errors.New("email belongs to another account")

type UserRepository struct {
	db *sqlx.DB
}

func NewUserRepository(db *sqlx.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(ctx context.Context, user *models.User) error {
	query := `INSERT INTO users (id, name, email, auth_subject, created_at)
		VALUES (:id, :name, :email, :auth_subject, :created_at)`
	_, err := r.db.NamedExecContext(ctx, query, user)
	return err
}

func (r *UserRepository) GetByID(ctx context.Context, id string) (*models.User, error) {
	var user models.User
	err := r.db.GetContext(ctx, &user, "SELECT * FROM users WHERE id = $1", id)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	err := r.db.GetContext(ctx, &user, "SELECT * FROM users WHERE email = $1", email)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *UserRepository) GetByAuthSubject(ctx context.Context, subject string) (*models.User, error) {
	var user models.User
	err := r.db.GetContext(ctx, &user, "SELECT * FROM users WHERE auth_subject = $1", subject)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// SessionActive reports whether a session token may still be used: its user
// exists and the token was not revoked by signing out.
func (r *UserRepository) SessionActive(ctx context.Context, userID, jti string) (bool, error) {
	var count int
	err := r.db.GetContext(ctx, &count, `SELECT COUNT(*) FROM users u
		WHERE u.id = $1 AND NOT EXISTS (SELECT 1 FROM revoked_sessions s WHERE s.jti = $2)`, userID, jti)
	return count > 0, err
}

// RevokeSession blocks a session token until it would have expired anyway.
func (r *UserRepository) RevokeSession(ctx context.Context, jti string, expiresAt time.Time) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO revoked_sessions (jti, expires_at) VALUES ($1, $2)
		ON CONFLICT (jti) DO NOTHING`, jti, expiresAt.UTC())
	return err
}

// PurgeExpiredRevocations drops revocations for tokens that have expired.
func (r *UserRepository) PurgeExpiredRevocations(ctx context.Context, now time.Time) (int64, error) {
	result, err := r.db.ExecContext(ctx, `DELETE FROM revoked_sessions WHERE expires_at < $1`, now.UTC())
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// UpsertFromOIDC finds the user by sign-in subject, refreshing name and email,
// or creates one. An email held by another subject is never linked.
func (r *UserRepository) UpsertFromOIDC(ctx context.Context, subject, email, name string) (*models.User, error) {
	if user, err := r.GetByAuthSubject(ctx, subject); err == nil {
		if user.Name != name || user.Email != email {
			if user.Email != email {
				if other, err := r.GetByEmail(ctx, email); err == nil && other.ID != user.ID {
					return nil, ErrEmailInUse
				} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
					return nil, err
				}
			}
			_, updateErr := r.db.ExecContext(ctx,
				`UPDATE users SET name = $1, email = $2 WHERE id = $3`,
				name, email, user.ID,
			)
			if updateErr != nil {
				return nil, updateErr
			}
			user.Name = name
			user.Email = email
		}
		return user, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	if _, err := r.GetByEmail(ctx, email); err == nil {
		return nil, ErrEmailInUse
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	user := &models.User{
		ID:          models.NewID(),
		Name:        name,
		Email:       email,
		AuthSubject: subject,
		CreatedAt:   time.Now(),
	}
	if err := r.Create(ctx, user); err != nil {
		return nil, err
	}
	return user, nil
}
