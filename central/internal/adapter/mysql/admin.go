package mysql

import (
	"context"
	"database/sql"
	"time"

	"netra-vuln/central/internal/domain"
)

func (s *Store) HostByID(ctx context.Context, id int64) (domain.Host, error) {
	return scanHost(s.q.QueryRowContext(ctx, `SELECT `+hostColumns+`
		FROM hosts h JOIN clients c ON c.id = h.client_id WHERE h.id = ?`, id))
}

func (s *Store) UpdateFindingTriage(ctx context.Context, id int64, status domain.TriageStatus, note string) error {
	var n any // NULL for an empty note
	if note != "" {
		n = note
	}
	res, err := s.q.ExecContext(ctx, `UPDATE findings SET status = ?, note = ? WHERE id = ?`, string(status), n, id)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 { // matched rows (ClientFoundRows)
		return domain.ErrNotFound
	}
	return nil
}

// --- admin users & sessions ---

func (s *Store) CreateAdminUser(ctx context.Context, username, passwordHash string, now time.Time) error {
	_, err := s.q.ExecContext(ctx,
		`INSERT INTO admin_users (username, password_hash, created_at) VALUES (?, ?, ?)`, username, passwordHash, now)
	return mapErr(err)
}

func scanAdmin(row interface{ Scan(...any) error }) (domain.AdminUser, error) {
	var u domain.AdminUser
	var disabled sql.NullTime
	err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.CreatedAt, &disabled)
	u.DisabledAt = nullTime(disabled)
	return u, mapErr(err)
}

func (s *Store) AdminUserByUsername(ctx context.Context, username string) (domain.AdminUser, error) {
	return scanAdmin(s.q.QueryRowContext(ctx,
		`SELECT id, username, password_hash, created_at, disabled_at FROM admin_users WHERE username = ?`, username))
}

func (s *Store) ListAdminUsers(ctx context.Context) ([]domain.AdminUser, error) {
	rows, err := s.q.QueryContext(ctx,
		`SELECT id, username, password_hash, created_at, disabled_at FROM admin_users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.AdminUser
	for rows.Next() {
		u, err := scanAdmin(rows)
		if err != nil {
			return nil, err
		}
		u.PasswordHash = "" // never needed by callers listing users
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) SetAdminPassword(ctx context.Context, username, passwordHash string) error {
	_, err := s.q.ExecContext(ctx, `UPDATE admin_users SET password_hash = ? WHERE username = ?`, passwordHash, username)
	return err
}

func (s *Store) InsertSession(ctx context.Context, userID int64, tokenHash []byte, now, expires time.Time) error {
	_, err := s.q.ExecContext(ctx,
		`INSERT INTO admin_sessions (user_id, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		userID, tokenHash, now, expires)
	return mapErr(err)
}

func (s *Store) SessionByTokenHash(ctx context.Context, tokenHash []byte, now time.Time) (domain.Session, error) {
	var sess domain.Session
	err := s.q.QueryRowContext(ctx, `SELECT u.id, u.username, s.expires_at
		FROM admin_sessions s JOIN admin_users u ON u.id = s.user_id
		WHERE s.token_hash = ? AND s.expires_at > ? AND u.disabled_at IS NULL`, tokenHash, now,
	).Scan(&sess.UserID, &sess.Username, &sess.ExpiresAt)
	return sess, mapErr(err)
}

func (s *Store) DeleteSession(ctx context.Context, tokenHash []byte) error {
	_, err := s.q.ExecContext(ctx, `DELETE FROM admin_sessions WHERE token_hash = ?`, tokenHash)
	return err
}

func (s *Store) DeleteExpiredSessions(ctx context.Context, now time.Time) error {
	_, err := s.q.ExecContext(ctx, `DELETE FROM admin_sessions WHERE expires_at <= ?`, now)
	return err
}
