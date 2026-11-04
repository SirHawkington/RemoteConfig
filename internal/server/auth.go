package server

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------- roles

// Role is what a user may do inside one project. Higher roles include lower ones.
type Role int

const (
	RoleNone Role = iota
	RoleViewer
	RoleOperator
	RoleAdmin
)

func (r Role) String() string {
	switch r {
	case RoleViewer:
		return "viewer"
	case RoleOperator:
		return "operator"
	case RoleAdmin:
		return "admin"
	}
	return "none"
}

func ParseRole(s string) (Role, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "viewer":
		return RoleViewer, true
	case "operator":
		return RoleOperator, true
	case "admin":
		return RoleAdmin, true
	}
	return RoleNone, false
}

// ---------------------------------------------------------------- model

// User is a dashboard account. A server admin (IsAdmin) administers every project and
// manages accounts; everyone else acts through per-project roles.
type User struct {
	ID          string    `json:"id"`
	Username    string    `json:"username"`
	DisplayName string    `json:"display_name"`
	IsAdmin     bool      `json:"is_admin"`
	Disabled    bool      `json:"disabled"`
	HasPassword bool      `json:"has_password"` // false for token-only accounts
	CreatedAt   time.Time `json:"created_at"`
	LastLogin   time.Time `json:"last_login,omitempty"`

	passHash string
}

type Session struct {
	ID        string     `json:"id"`
	Kind      string     `json:"kind"` // session (dashboard login) | api (personal access token)
	Name      string     `json:"name"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	LastUsed  time.Time  `json:"last_used,omitempty"`

	hash   string
	userID string
}

var (
	ErrExists      = errors.New("already exists")
	ErrNotFound    = errors.New("not found")
	ErrLastAdmin   = errors.New("this would leave the server without an enabled administrator")
	ErrBadPassword = errors.New("password must be 10 to 200 characters and not contain the username")
)

const (
	sessionIdleTimeout = 7 * 24 * time.Hour  // a dashboard login unused this long expires
	sessionMaxAge      = 30 * 24 * time.Hour // and no login lives longer than this
	auditKeep          = 20000
)

const authSchema = `
CREATE TABLE IF NOT EXISTS users (
	id TEXT PRIMARY KEY,
	username TEXT NOT NULL UNIQUE,
	display_name TEXT NOT NULL DEFAULT '',
	is_admin INTEGER NOT NULL DEFAULT 0,
	disabled INTEGER NOT NULL DEFAULT 0,
	pass_hash TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	last_login TEXT
);
CREATE TABLE IF NOT EXISTS members (
	project TEXT NOT NULL,
	user_id TEXT NOT NULL,
	role TEXT NOT NULL,
	PRIMARY KEY (project, user_id)
);
CREATE TABLE IF NOT EXISTS sessions (
	hash TEXT PRIMARY KEY,
	id TEXT NOT NULL UNIQUE,
	user_id TEXT NOT NULL,
	kind TEXT NOT NULL,
	name TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	expires_at TEXT,
	last_used TEXT NOT NULL,
	user_agent TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS audit (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	ts TEXT NOT NULL,
	user_id TEXT NOT NULL DEFAULT '',
	username TEXT NOT NULL DEFAULT '',
	action TEXT NOT NULL,
	project TEXT NOT NULL DEFAULT '',
	target TEXT NOT NULL DEFAULT '',
	detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS audit_project ON audit(project, id DESC);
`

// ---------------------------------------------------------------- passwords and tokens

// passwordCost is the PBKDF2 iteration count (OWASP's figure for PBKDF2-HMAC-SHA256).
// It is stored inside every hash, so raising it later keeps old hashes verifiable.
var passwordCost = 600_000

// SetPasswordCost lowers the hashing cost. For tests only: a real server must not.
func SetPasswordCost(n int) { passwordCost = n }

func b64(b []byte) string { return base64.RawStdEncoding.EncodeToString(b) }

func hashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, pw, salt, passwordCost, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", passwordCost, b64(salt), b64(key)), nil
}

func checkPassword(hash, pw string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1 {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[2])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[3])
	if err1 != nil || err2 != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, pw, salt, iter, len(want))
	return err == nil && subtle.ConstantTimeCompare(got, want) == 1
}

func validPassword(username, pw string) error {
	if len(pw) < 10 || len(pw) > 200 || (username != "" && strings.Contains(strings.ToLower(pw), strings.ToLower(username))) {
		return ErrBadPassword
	}
	return nil
}

// GeneratePassword returns a random password a person can type: 16 characters, no look-alikes.
func GeneratePassword() string {
	const alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 16)
	rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

func newSecret(prefix string) string { return prefix + NewToken(32) }

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

func normUsername(u string) string { return strings.ToLower(strings.TrimSpace(u)) }

func validUsername(u string) bool {
	if len(u) < 2 || len(u) > 40 {
		return false
	}
	for _, r := range u {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' || r == '@') {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------- users

const userCols = `id,username,display_name,is_admin,disabled,pass_hash,created_at,COALESCE(last_login,'')`

func scanUser(sc interface{ Scan(...any) error }) (*User, error) {
	var u User
	var admin, disabled int
	var created, last string
	if err := sc.Scan(&u.ID, &u.Username, &u.DisplayName, &admin, &disabled, &u.passHash, &created, &last); err != nil {
		return nil, err
	}
	u.IsAdmin, u.Disabled, u.HasPassword = admin == 1, disabled == 1, u.passHash != ""
	u.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	u.LastLogin, _ = time.Parse(time.RFC3339Nano, last)
	return &u, nil
}

func (s *Store) userByName(name string) (*User, error) {
	u, err := scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE username=?`, normUsername(name)))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

func (s *Store) userByID(id string) (*User, error) {
	u, err := scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

func (s *Store) listUsers() ([]User, error) {
	rows, err := s.db.Query(`SELECT ` + userCols + ` FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

// CreateUser adds an account. An empty password makes a token-only account (it cannot
// log in to the dashboard; it can hold API tokens).
func (s *Store) CreateUser(username, displayName, password string, isAdmin bool) (*User, error) {
	username = normUsername(username)
	if !validUsername(username) {
		return nil, errors.New("username must be 2-40 characters: letters, digits, . _ - @")
	}
	hash := ""
	if password != "" {
		if err := validPassword(username, password); err != nil {
			return nil, err
		}
		var err error
		if hash, err = hashPassword(password); err != nil {
			return nil, err
		}
	}
	if displayName = strings.TrimSpace(displayName); displayName == "" {
		displayName = username
	}
	u := &User{ID: "usr_" + NewToken(6), Username: username, DisplayName: displayName, IsAdmin: isAdmin, CreatedAt: time.Now().UTC(), passHash: hash}
	_, err := s.db.Exec(`INSERT INTO users(id,username,display_name,is_admin,disabled,pass_hash,created_at) VALUES(?,?,?,?,0,?,?)`,
		u.ID, u.Username, u.DisplayName, b2i(isAdmin), hash, u.CreatedAt.Format(time.RFC3339Nano))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, fmt.Errorf("user %q %w", username, ErrExists)
		}
		return nil, err
	}
	u.HasPassword = hash != ""
	return u, nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (s *Store) enabledAdmins() int {
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE is_admin=1 AND disabled=0`).Scan(&n)
	return n
}

// UserPatch changes a user; nil fields are left alone.
type UserPatch struct {
	DisplayName *string `json:"display_name,omitempty"`
	IsAdmin     *bool   `json:"is_admin,omitempty"`
	Disabled    *bool   `json:"disabled,omitempty"`
	Password    *string `json:"password,omitempty"`
}

func (s *Store) updateUser(u *User, p UserPatch) error {
	if p.IsAdmin != nil || p.Disabled != nil {
		admin, disabled := u.IsAdmin, u.Disabled
		if p.IsAdmin != nil {
			admin = *p.IsAdmin
		}
		if p.Disabled != nil {
			disabled = *p.Disabled
		}
		wasEnabledAdmin := u.IsAdmin && !u.Disabled
		willBeEnabledAdmin := admin && !disabled
		if wasEnabledAdmin && !willBeEnabledAdmin && s.enabledAdmins() <= 1 {
			return ErrLastAdmin
		}
		if _, err := s.db.Exec(`UPDATE users SET is_admin=?, disabled=? WHERE id=?`, b2i(admin), b2i(disabled), u.ID); err != nil {
			return err
		}
		if disabled {
			s.revokeUserSessions(u.ID, "", true) // a disabled user is out immediately, API tokens included
		}
	}
	if p.DisplayName != nil {
		if _, err := s.db.Exec(`UPDATE users SET display_name=? WHERE id=?`, strings.TrimSpace(*p.DisplayName), u.ID); err != nil {
			return err
		}
	}
	if p.Password != nil {
		if err := s.setPassword(u, *p.Password); err != nil {
			return err
		}
	}
	return nil
}

// setPassword changes the password and signs the user out of every dashboard session.
func (s *Store) setPassword(u *User, pw string) error { return s.setPasswordKeeping(u, pw, "") }

// setPasswordKeeping is setPassword but leaves the session with hash keepHash signed in:
// the one the user just changed their own password from.
func (s *Store) setPasswordKeeping(u *User, pw, keepHash string) error {
	if err := validPassword(u.Username, pw); err != nil {
		return err
	}
	hash, err := hashPassword(pw)
	if err != nil {
		return err
	}
	if _, err := s.db.Exec(`UPDATE users SET pass_hash=? WHERE id=?`, hash, u.ID); err != nil {
		return err
	}
	s.revokeUserSessions(u.ID, keepHash, false)
	return nil
}

func (s *Store) deleteUser(u *User) error {
	if u.IsAdmin && !u.Disabled && s.enabledAdmins() <= 1 {
		return ErrLastAdmin
	}
	s.revokeUserSessions(u.ID, "", true)
	s.db.Exec(`DELETE FROM members WHERE user_id=?`, u.ID)
	_, err := s.db.Exec(`DELETE FROM users WHERE id=?`, u.ID)
	return err
}

// ---------------------------------------------------------------- project membership

type Member struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Role        string `json:"role"`
	Disabled    bool   `json:"disabled"`
}

func (s *Store) setMember(project string, u *User, role Role) error {
	_, err := s.db.Exec(`INSERT INTO members(project,user_id,role) VALUES(?,?,?) ON CONFLICT(project,user_id) DO UPDATE SET role=excluded.role`,
		project, u.ID, role.String())
	return err
}

func (s *Store) removeMember(project string, u *User) error {
	_, err := s.db.Exec(`DELETE FROM members WHERE project=? AND user_id=?`, project, u.ID)
	return err
}

func (s *Store) listMembers(project string) ([]Member, error) {
	rows, err := s.db.Query(`SELECT u.username,u.display_name,m.role,u.disabled FROM members m JOIN users u ON u.id=m.user_id WHERE m.project=? ORDER BY u.username`, project)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Member{}
	for rows.Next() {
		var m Member
		var dis int
		if err := rows.Scan(&m.Username, &m.DisplayName, &m.Role, &dis); err != nil {
			return nil, err
		}
		m.Disabled = dis == 1
		out = append(out, m)
	}
	return out, rows.Err()
}

// roleIn is the user's role in a project: admin everywhere for a server admin.
func (s *Store) roleIn(u *User, project string) Role {
	if u.IsAdmin {
		return RoleAdmin
	}
	var r string
	if err := s.db.QueryRow(`SELECT role FROM members WHERE project=? AND user_id=?`, project, u.ID).Scan(&r); err != nil {
		return RoleNone
	}
	role, _ := ParseRole(r)
	return role
}

// rolesOf lists the user's explicit memberships.
func (s *Store) rolesOf(u *User) map[string]Role {
	out := map[string]Role{}
	rows, err := s.db.Query(`SELECT project, role FROM members WHERE user_id=?`, u.ID)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var p, r string
		if rows.Scan(&p, &r) == nil {
			role, _ := ParseRole(r)
			out[p] = role
		}
	}
	return out
}

// ---------------------------------------------------------------- sessions and API tokens

// createSession issues a token for the user. kind "session" is a dashboard login (idle and
// absolute expiry); kind "api" is a personal access token (expires only if ttl > 0).
// The token itself is returned once and never stored: only its hash is.
func (s *Store) createSession(u *User, kind, name, userAgent string, ttl time.Duration) (token string, sess *Session, err error) {
	prefix := "rcs_"
	if kind == "api" {
		prefix = "rct_"
	}
	token = newSecret(prefix)
	now := time.Now().UTC()
	sess = &Session{ID: "tok_" + NewToken(4), Kind: kind, Name: name, CreatedAt: now, LastUsed: now, hash: hashToken(token), userID: u.ID}
	var exp any
	if ttl > 0 {
		t := now.Add(ttl)
		sess.ExpiresAt = &t
		exp = t.Format(time.RFC3339Nano)
	}
	_, err = s.db.Exec(`INSERT INTO sessions(hash,id,user_id,kind,name,created_at,expires_at,last_used,user_agent) VALUES(?,?,?,?,?,?,?,?,?)`,
		sess.hash, sess.ID, u.ID, kind, name, now.Format(time.RFC3339Nano), exp, now.Format(time.RFC3339Nano), truncate(userAgent, 200))
	return token, sess, err
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// lookupToken resolves a bearer token to its user, enforcing expiry and disabled accounts.
// A dashboard session also expires after sessionIdleTimeout without use.
func (s *Store) lookupToken(token string) (*User, *Session, error) {
	if token == "" {
		return nil, nil, ErrNotFound
	}
	var sess Session
	var created, exp, last string
	var expNull sql.NullString
	err := s.db.QueryRow(`SELECT id,user_id,kind,name,created_at,expires_at,last_used,hash FROM sessions WHERE hash=?`, hashToken(token)).
		Scan(&sess.ID, &sess.userID, &sess.Kind, &sess.Name, &created, &expNull, &last, &sess.hash)
	if err != nil {
		return nil, nil, ErrNotFound
	}
	exp = expNull.String
	sess.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	sess.LastUsed, _ = time.Parse(time.RFC3339Nano, last)
	now := time.Now().UTC()
	if exp != "" {
		t, _ := time.Parse(time.RFC3339Nano, exp)
		sess.ExpiresAt = &t
		if now.After(t) {
			s.db.Exec(`DELETE FROM sessions WHERE hash=?`, sess.hash)
			return nil, nil, ErrNotFound
		}
	}
	if sess.Kind == "session" && now.Sub(sess.LastUsed) > sessionIdleTimeout {
		s.db.Exec(`DELETE FROM sessions WHERE hash=?`, sess.hash)
		return nil, nil, ErrNotFound
	}
	u, err := s.userByID(sess.userID)
	if err != nil || u.Disabled {
		return nil, nil, ErrNotFound
	}
	if now.Sub(sess.LastUsed) > time.Minute { // slide the idle window, without a write per request
		s.db.Exec(`UPDATE sessions SET last_used=? WHERE hash=?`, now.Format(time.RFC3339Nano), sess.hash)
		sess.LastUsed = now
	}
	return u, &sess, nil
}

// revokeUserSessions signs a user out. except keeps one session (the current one);
// includeAPI also revokes personal access tokens.
func (s *Store) revokeUserSessions(userID, exceptHash string, includeAPI bool) {
	q := `DELETE FROM sessions WHERE user_id=? AND hash<>?`
	if !includeAPI {
		q += ` AND kind='session'`
	}
	s.db.Exec(q, userID, exceptHash)
}

func (s *Store) revokeToken(userID, id string) bool {
	res, err := s.db.Exec(`DELETE FROM sessions WHERE user_id=? AND id=? AND kind='api'`, userID, id)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}

func (s *Store) revokeSessionByHash(hash string) {
	s.db.Exec(`DELETE FROM sessions WHERE hash=?`, hash)
}

func (s *Store) listAPITokens(userID string) []Session {
	rows, err := s.db.Query(`SELECT id,name,created_at,expires_at,last_used FROM sessions WHERE user_id=? AND kind='api' ORDER BY created_at`, userID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []Session{}
	for rows.Next() {
		var t Session
		var created, last string
		var exp sql.NullString
		if rows.Scan(&t.ID, &t.Name, &created, &exp, &last) != nil {
			continue
		}
		t.Kind = "api"
		t.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		t.LastUsed, _ = time.Parse(time.RFC3339Nano, last)
		if exp.Valid {
			e, _ := time.Parse(time.RFC3339Nano, exp.String)
			t.ExpiresAt = &e
		}
		out = append(out, t)
	}
	return out
}

// ---------------------------------------------------------------- audit

type AuditEntry struct {
	ID       int64     `json:"id"`
	Time     time.Time `json:"time"`
	Username string    `json:"username"`
	Action   string    `json:"action"`
	Project  string    `json:"project,omitempty"`
	Target   string    `json:"target,omitempty"`
	Detail   string    `json:"detail,omitempty"`
}

// Audit records who did what. It never fails the request it describes.
func (s *Store) Audit(u *User, action, project, target, detail string) {
	uid, name := "", ""
	if u != nil {
		uid, name = u.ID, u.Username
	}
	s.db.Exec(`INSERT INTO audit(ts,user_id,username,action,project,target,detail) VALUES(?,?,?,?,?,?,?)`,
		time.Now().UTC().Format(time.RFC3339Nano), uid, name, action, project, truncate(target, 200), truncate(detail, 500))
}

// listAudit returns newest first. project "" means every project (a server admin's view);
// otherwise that project's entries.
func (s *Store) listAudit(project string, limit int) []AuditEntry {
	q := `SELECT id,ts,username,action,project,target,detail FROM audit`
	args := []any{}
	if project != "" {
		q += ` WHERE project=?`
		args = append(args, project)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		var ts string
		if rows.Scan(&e.ID, &ts, &e.Username, &e.Action, &e.Project, &e.Target, &e.Detail) == nil {
			e.Time, _ = time.Parse(time.RFC3339Nano, ts)
			out = append(out, e)
		}
	}
	return out
}

func (s *Store) pruneAuth() {
	s.db.Exec(`DELETE FROM sessions WHERE expires_at IS NOT NULL AND expires_at < ?`, time.Now().UTC().Format(time.RFC3339Nano))
	s.db.Exec(`DELETE FROM sessions WHERE kind='session' AND last_used < ?`, time.Now().Add(-sessionIdleTimeout).UTC().Format(time.RFC3339Nano))
	s.db.Exec(`DELETE FROM audit WHERE id <= COALESCE((SELECT id FROM audit ORDER BY id DESC LIMIT 1 OFFSET ?), 0)`, auditKeep)
}

// ---------------------------------------------------------------- operations for the command line
// (`server user ...` works on the database file directly, so it needs no running server and
// no existing login: whoever can read and write the file is already the owner.)

func (s *Store) Users() ([]User, error) { return s.listUsers() }

func (s *Store) UpdateUser(username string, p UserPatch) error {
	u, err := s.userByName(username)
	if err != nil {
		return err
	}
	return s.updateUser(u, p)
}

func (s *Store) DeleteUser(username string) error {
	u, err := s.userByName(username)
	if err != nil {
		return err
	}
	return s.deleteUser(u)
}

// SetProjectRole grants a role in a project; RoleNone removes the membership.
func (s *Store) SetProjectRole(project, username string, role Role) error {
	u, err := s.userByName(username)
	if err != nil {
		return err
	}
	s.mu.Lock()
	_, ok := s.D.Projects[project]
	s.mu.Unlock()
	if !ok {
		return fmt.Errorf("project %q: %w", project, ErrNotFound)
	}
	if role == RoleNone {
		return s.removeMember(project, u)
	}
	return s.setMember(project, u, role)
}

// ---------------------------------------------------------------- bootstrap

// EnsureLegacyAdminToken keeps scripts that used the old shared admin token working: it
// becomes a personal access token (hashed, like any other) of a server-admin user called
// "admin", which is created without a password if it does not exist.
func (s *Store) EnsureLegacyAdminToken(token string) error {
	u, err := s.userByName("admin")
	if errors.Is(err, ErrNotFound) {
		if u, err = s.CreateUser("admin", "Administrator", "", true); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT OR IGNORE INTO sessions(hash,id,user_id,kind,name,created_at,expires_at,last_used) VALUES(?,?,?,?,?,?,NULL,?)`,
		hashToken(token), "tok_"+NewToken(4), u.ID, "api", "bootstrap (-admin-token)", time.Now().UTC().Format(time.RFC3339Nano), time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// EnsureAdminLogin makes sure the "admin" account can sign in with a password. On a fresh
// database it creates the account. If the account exists without a password (it came from
// the legacy token) it gets one. It returns the password it set, or "" if nothing changed.
// An empty password argument means "generate one".
func (s *Store) EnsureAdminLogin(password string) (set string, err error) {
	u, err := s.userByName("admin")
	if errors.Is(err, ErrNotFound) {
		if n := s.enabledAdmins(); n > 0 {
			return "", nil // someone else already administers this server
		}
		if password == "" {
			password = GeneratePassword()
		}
		_, err = s.CreateUser("admin", "Administrator", password, true)
		return password, err
	}
	if err != nil {
		return "", err
	}
	if u.HasPassword {
		return "", nil
	}
	if password == "" {
		password = GeneratePassword()
	}
	return password, s.setPassword(u, password)
}

// Verify checks a username and password, returning the user on success. It spends the
// same time whether or not the user exists, so response time does not reveal usernames.
func (s *Store) Verify(username, password string) (*User, bool) {
	u, err := s.userByName(username)
	if err != nil || !u.HasPassword {
		checkPassword(dummyHash(), password)
		return nil, false
	}
	if !checkPassword(u.passHash, password) || u.Disabled {
		return nil, false
	}
	return u, true
}

var dummy string

func dummyHash() string {
	if dummy == "" || !strings.Contains(dummy, fmt.Sprintf("$%d$", passwordCost)) {
		dummy, _ = hashPassword("not-a-real-password")
	}
	return dummy
}

func (s *Store) touchLogin(u *User) {
	s.db.Exec(`UPDATE users SET last_login=? WHERE id=?`, time.Now().UTC().Format(time.RFC3339Nano), u.ID)
}
