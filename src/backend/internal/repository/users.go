package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/roomies/backend/internal/models"
)

// ErrEmailInUse means the email already belongs to a different sign-in identity.
var ErrEmailInUse = errors.New("email belongs to another account")

type UserRepository struct {
	db *sqlx.DB
}

func NewUserRepository(db *sqlx.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(ctx context.Context, user *models.User) error {
	query := `INSERT INTO users (id, name, email, auth_issuer, auth_subject, created_at)
		VALUES (:id, :name, :email, :auth_issuer, :auth_subject, :created_at)`
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

func (r *UserRepository) GetByAuthIdentity(ctx context.Context, issuer, subject string) (*models.User, error) {
	var user models.User
	err := r.db.GetContext(ctx, &user, "SELECT * FROM users WHERE auth_issuer = $1 AND auth_subject = $2", issuer, subject)
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

// SaveSessionIDToken keeps the provider ID token of session jti, and the
// issuer that minted it, as the session's logout hint until it expires.
func (r *UserRepository) SaveSessionIDToken(ctx context.Context, jti, issuer, idToken string, expiresAt time.Time) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO session_id_tokens (jti, issuer, id_token, expires_at) VALUES ($1, $2, $3, $4)`,
		jti, issuer, idToken, expiresAt.UTC())
	return err
}

// EndSession revokes session jti until it would have expired anyway and takes
// its logout hint, in one transaction: on error neither happens, so a retry
// still finds the hint. issuer and idToken are "" when there is no hint.
func (r *UserRepository) EndSession(ctx context.Context, jti string, expiresAt time.Time) (issuer, idToken string, err error) {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return "", "", err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO revoked_sessions (jti, expires_at) VALUES ($1, $2)
		ON CONFLICT (jti) DO NOTHING`, jti, expiresAt.UTC()); err != nil {
		return "", "", err
	}
	var hint struct {
		Issuer  string `db:"issuer"`
		IDToken string `db:"id_token"`
	}
	err = tx.GetContext(ctx, &hint, `DELETE FROM session_id_tokens WHERE jti = $1 RETURNING issuer, id_token`, jti)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", "", err
	}
	if err := tx.Commit(); err != nil {
		return "", "", err
	}
	return hint.Issuer, hint.IDToken, nil
}

// PurgeExpiredSessionIDTokens drops logout hints of expired sessions.
func (r *UserRepository) PurgeExpiredSessionIDTokens(ctx context.Context, now time.Time) (int64, error) {
	result, err := r.db.ExecContext(ctx, `DELETE FROM session_id_tokens WHERE expires_at < $1`, now.UTC())
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// PurgeExpiredRevocations drops revocations for tokens that have expired.
func (r *UserRepository) PurgeExpiredRevocations(ctx context.Context, now time.Time) (int64, error) {
	result, err := r.db.ExecContext(ctx, `DELETE FROM revoked_sessions WHERE expires_at < $1`, now.UTC())
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// UpsertFromOIDC finds the user by issuer and subject, refreshing name and
// email, or creates one. An email held by another identity is never linked.
func (r *UserRepository) UpsertFromOIDC(ctx context.Context, issuer, subject, email, name string) (*models.User, error) {
	if user, err := r.GetByAuthIdentity(ctx, issuer, subject); err == nil {
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
		AuthIssuer:  issuer,
		AuthSubject: subject,
		CreatedAt:   time.Now(),
	}
	if err := r.Create(ctx, user); err != nil {
		return nil, err
	}
	return user, nil
}
