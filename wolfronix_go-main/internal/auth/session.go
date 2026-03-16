package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"
)

var (
	ErrInvalidToken      = errors.New("invalid token")
	ErrSessionExpired    = errors.New("session expired")
	ErrSessionRevoked    = errors.New("session revoked")
	ErrRefreshTokenReuse = errors.New("refresh token reuse detected")
	ErrClientMismatch    = errors.New("client mismatch")
	ErrChallengeExpired  = errors.New("challenge expired")
	ErrChallengeUsed     = errors.New("challenge already used")
)

type Session struct {
	ID                 int64
	ClientID           string
	UserID             string
	SessionID          string
	AccessTokenHash    string
	RefreshTokenHash   string
	AccessExpiresAt    time.Time
	RefreshExpiresAt   time.Time
	CreatedAt          time.Time
	UpdatedAt          time.Time
	RevokedAt          sql.NullTime
	RefreshRotatedAt   sql.NullTime
	LastSeenAt         sql.NullTime
	CreatedByIPHash    string
	CreatedByUserAgent string
}

type SessionTokens struct {
	AccessToken          string
	RefreshToken         string
	TokenType            string
	ExpiresInSeconds     int64
	RefreshExpiresInSecs int64
	AccessExpiresAt      time.Time
	RefreshExpiresAt     time.Time
}

type SessionStore struct {
	db         *sql.DB
	accessTTL  time.Duration
	refreshTTL time.Duration
}

type AuthChallenge struct {
	ChallengeID string
	Purpose     string
	ExpiresAt   time.Time
}

func NewSessionStore(db *sql.DB, accessTTL, refreshTTL time.Duration) (*SessionStore, error) {
	s := &SessionStore{
		db:         db,
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
	}
	if err := s.initDB(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *SessionStore) initDB() error {
	query := `
	CREATE TABLE IF NOT EXISTS auth_sessions (
		id BIGSERIAL PRIMARY KEY,
		client_id VARCHAR(255) NOT NULL,
		user_id VARCHAR(255) NOT NULL,
		session_id VARCHAR(64) NOT NULL,
		access_token_hash VARCHAR(64) NOT NULL UNIQUE,
		refresh_token_hash VARCHAR(64) NOT NULL UNIQUE,
		access_expires_at TIMESTAMP NOT NULL,
		refresh_expires_at TIMESTAMP NOT NULL,
		created_by_ip_hash VARCHAR(64) DEFAULT '',
		created_by_user_agent VARCHAR(512) DEFAULT '',
		last_seen_at TIMESTAMP NULL,
		refresh_rotated_at TIMESTAMP NULL,
		revoked_at TIMESTAMP NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_auth_sessions_client_user ON auth_sessions(client_id, user_id);
	CREATE INDEX IF NOT EXISTS idx_auth_sessions_session_id ON auth_sessions(session_id);
	CREATE INDEX IF NOT EXISTS idx_auth_sessions_access_expiry ON auth_sessions(access_expires_at);
	CREATE INDEX IF NOT EXISTS idx_auth_sessions_refresh_expiry ON auth_sessions(refresh_expires_at);

	CREATE TABLE IF NOT EXISTS auth_audit_logs (
		id BIGSERIAL PRIMARY KEY,
		client_id VARCHAR(255) NOT NULL,
		user_id VARCHAR(255) NOT NULL,
		session_id VARCHAR(64) DEFAULT '',
		event_type VARCHAR(64) NOT NULL,
		status VARCHAR(32) NOT NULL,
		ip_hash VARCHAR(64) DEFAULT '',
		user_agent VARCHAR(512) DEFAULT '',
		details TEXT DEFAULT '',
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
		CREATE INDEX IF NOT EXISTS idx_auth_audit_client_user ON auth_audit_logs(client_id, user_id);
		CREATE INDEX IF NOT EXISTS idx_auth_audit_event ON auth_audit_logs(event_type, created_at);

		CREATE TABLE IF NOT EXISTS auth_challenges (
			id BIGSERIAL PRIMARY KEY,
			challenge_id VARCHAR(128) NOT NULL UNIQUE,
			client_id VARCHAR(255) NOT NULL,
			user_id VARCHAR(255) NOT NULL,
			purpose VARCHAR(64) NOT NULL,
			expires_at TIMESTAMP NOT NULL,
			consumed_at TIMESTAMP NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_auth_challenges_lookup ON auth_challenges(challenge_id, client_id, user_id, purpose);
		CREATE INDEX IF NOT EXISTS idx_auth_challenges_expiry ON auth_challenges(expires_at);
		`
	_, err := s.db.Exec(query)
	return err
}

func randomToken(byteLen int) (string, error) {
	buf := make([]byte, byteLen)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func hashSafeString(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func (s *SessionStore) recordAudit(clientID, userID, sessionID, eventType, status, ip, userAgent, details string) {
	_, _ = s.db.Exec(
		`INSERT INTO auth_audit_logs (client_id, user_id, session_id, event_type, status, ip_hash, user_agent, details)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		clientID, userID, sessionID, eventType, status, hashSafeString(ip), userAgent, details,
	)
}

func (s *SessionStore) IssueSession(clientID, userID, ip, userAgent string) (*SessionTokens, error) {
	accessToken, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	refreshToken, err := randomToken(48)
	if err != nil {
		return nil, err
	}
	sessionID, err := randomToken(16)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	accessExp := now.Add(s.accessTTL)
	refreshExp := now.Add(s.refreshTTL)
	accessHash := hashToken(accessToken)
	refreshHash := hashToken(refreshToken)
	ipHash := hashSafeString(ip)

	_, err = s.db.Exec(
		`INSERT INTO auth_sessions
		 (client_id, user_id, session_id, access_token_hash, refresh_token_hash, access_expires_at, refresh_expires_at, created_by_ip_hash, created_by_user_agent)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		clientID, userID, sessionID, accessHash, refreshHash, accessExp, refreshExp, ipHash, userAgent,
	)
	if err != nil {
		return nil, err
	}

	s.recordAudit(clientID, userID, sessionID, "session_issued", "success", ip, userAgent, "")
	return &SessionTokens{
		AccessToken:          accessToken,
		RefreshToken:         refreshToken,
		TokenType:            "Bearer",
		ExpiresInSeconds:     int64(s.accessTTL.Seconds()),
		RefreshExpiresInSecs: int64(s.refreshTTL.Seconds()),
		AccessExpiresAt:      accessExp,
		RefreshExpiresAt:     refreshExp,
	}, nil
}

func (s *SessionStore) ValidateAccessToken(token string) (*Session, error) {
	hash := hashToken(token)
	row := s.db.QueryRow(
		`SELECT id, client_id, user_id, session_id, access_token_hash, refresh_token_hash, access_expires_at, refresh_expires_at,
		        created_at, updated_at, revoked_at, refresh_rotated_at, last_seen_at, created_by_ip_hash, created_by_user_agent
		   FROM auth_sessions
		  WHERE access_token_hash = $1`,
		hash,
	)

	var sess Session
	err := row.Scan(
		&sess.ID, &sess.ClientID, &sess.UserID, &sess.SessionID, &sess.AccessTokenHash, &sess.RefreshTokenHash,
		&sess.AccessExpiresAt, &sess.RefreshExpiresAt, &sess.CreatedAt, &sess.UpdatedAt, &sess.RevokedAt,
		&sess.RefreshRotatedAt, &sess.LastSeenAt, &sess.CreatedByIPHash, &sess.CreatedByUserAgent,
	)
	if err == sql.ErrNoRows {
		return nil, ErrInvalidToken
	}
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	if sess.RevokedAt.Valid {
		return nil, ErrSessionRevoked
	}
	if now.After(sess.AccessExpiresAt) {
		return nil, ErrSessionExpired
	}

	_, _ = s.db.Exec(`UPDATE auth_sessions SET last_seen_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = $1`, sess.ID)
	return &sess, nil
}

func (s *SessionStore) RefreshSession(refreshToken, expectedClientID, ip, userAgent string) (*SessionTokens, error) {
	refreshHash := hashToken(refreshToken)
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	row := tx.QueryRowContext(ctx,
		`SELECT id, client_id, user_id, session_id, refresh_expires_at, revoked_at, refresh_rotated_at
		   FROM auth_sessions
		  WHERE refresh_token_hash = $1
		  FOR UPDATE`,
		refreshHash,
	)
	var (
		id               int64
		clientID         string
		userID           string
		sessionID        string
		refreshExp       time.Time
		revokedAt        sql.NullTime
		refreshRotatedAt sql.NullTime
	)
	if err := row.Scan(&id, &clientID, &userID, &sessionID, &refreshExp, &revokedAt, &refreshRotatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrInvalidToken
		}
		return nil, err
	}

	now := time.Now().UTC()
	if revokedAt.Valid {
		return nil, ErrSessionRevoked
	}
	if expectedClientID != "" && clientID != expectedClientID {
		return nil, ErrClientMismatch
	}
	if now.After(refreshExp) {
		return nil, ErrSessionExpired
	}
	if refreshRotatedAt.Valid {
		// Rotation reuse detected â€” revoke the session.
		_, _ = tx.ExecContext(ctx, `UPDATE auth_sessions SET revoked_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = $1`, id)
		_ = tx.Commit()
		s.recordAudit(clientID, userID, sessionID, "refresh_reuse", "blocked", ip, userAgent, "")
		return nil, ErrRefreshTokenReuse
	}

	newAccess, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	newRefresh, err := randomToken(48)
	if err != nil {
		return nil, err
	}
	newSessionID, err := randomToken(16)
	if err != nil {
		return nil, err
	}
	newAccessExp := now.Add(s.accessTTL)
	newRefreshExp := now.Add(s.refreshTTL)

	// Mark old refresh as rotated and revoked.
	if _, err := tx.ExecContext(ctx,
		`UPDATE auth_sessions
		    SET refresh_rotated_at = CURRENT_TIMESTAMP, revoked_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
		  WHERE id = $1`,
		id,
	); err != nil {
		return nil, err
	}

	// Insert a new session row.
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO auth_sessions
		 (client_id, user_id, session_id, access_token_hash, refresh_token_hash, access_expires_at, refresh_expires_at, created_by_ip_hash, created_by_user_agent)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		clientID, userID, newSessionID, hashToken(newAccess), hashToken(newRefresh), newAccessExp, newRefreshExp, hashSafeString(ip), userAgent,
	); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	s.recordAudit(clientID, userID, sessionID, "refresh", "success", ip, userAgent, "")
	return &SessionTokens{
		AccessToken:          newAccess,
		RefreshToken:         newRefresh,
		TokenType:            "Bearer",
		ExpiresInSeconds:     int64(s.accessTTL.Seconds()),
		RefreshExpiresInSecs: int64(s.refreshTTL.Seconds()),
		AccessExpiresAt:      newAccessExp,
		RefreshExpiresAt:     newRefreshExp,
	}, nil
}

func (s *SessionStore) RevokeAccessToken(accessToken, expectedClientID, ip, userAgent string) error {
	hash := hashToken(accessToken)
	row := s.db.QueryRow(`SELECT id, client_id, user_id, session_id FROM auth_sessions WHERE access_token_hash = $1`, hash)
	var (
		id        int64
		clientID  string
		userID    string
		sessionID string
	)
	if err := row.Scan(&id, &clientID, &userID, &sessionID); err != nil {
		if err == sql.ErrNoRows {
			return ErrInvalidToken
		}
		return err
	}
	if expectedClientID != "" && clientID != expectedClientID {
		return ErrClientMismatch
	}

	_, err := s.db.Exec(`UPDATE auth_sessions SET revoked_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = $1`, id)
	if err == nil {
		s.recordAudit(clientID, userID, sessionID, "logout", "success", ip, userAgent, "")
	}
	return err
}

func (s *SessionStore) IssueChallenge(clientID, userID, purpose string, ttl time.Duration) (*AuthChallenge, error) {
	challengeID, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	expiresAt := time.Now().UTC().Add(ttl)
	_, err = s.db.Exec(
		`INSERT INTO auth_challenges (challenge_id, client_id, user_id, purpose, expires_at)
		 VALUES ($1,$2,$3,$4,$5)`,
		challengeID, clientID, userID, purpose, expiresAt,
	)
	if err != nil {
		return nil, err
	}
	return &AuthChallenge{
		ChallengeID: challengeID,
		Purpose:     purpose,
		ExpiresAt:   expiresAt,
	}, nil
}

func (s *SessionStore) ConsumeChallenge(challengeID, clientID, userID, purpose string) error {
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()

	row := tx.QueryRowContext(
		ctx,
		`SELECT expires_at, consumed_at
		   FROM auth_challenges
		  WHERE challenge_id = $1 AND client_id = $2 AND user_id = $3 AND purpose = $4
		  FOR UPDATE`,
		challengeID, clientID, userID, purpose,
	)
	var (
		expiresAt  time.Time
		consumedAt sql.NullTime
	)
	if err := row.Scan(&expiresAt, &consumedAt); err != nil {
		if err == sql.ErrNoRows {
			return ErrInvalidToken
		}
		return err
	}
	if consumedAt.Valid {
		return ErrChallengeUsed
	}
	if time.Now().UTC().After(expiresAt) {
		return ErrChallengeExpired
	}
	if _, err := tx.ExecContext(
		ctx,
		`UPDATE auth_challenges SET consumed_at = CURRENT_TIMESTAMP WHERE challenge_id = $1`,
		challengeID,
	); err != nil {
		return err
	}
	return tx.Commit()
}

func ParseBearerToken(authz string) (string, error) {
	const prefix = "Bearer "
	if len(authz) <= len(prefix) || authz[:len(prefix)] != prefix {
		return "", fmt.Errorf("invalid authorization header")
	}
	return authz[len(prefix):], nil
}
