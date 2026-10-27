package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/thakur-vijay/adorbit-go/response"
)

type Session struct {
	UserID    string
	SessionID string
}

type SessionValidator interface {
	ValidateAccessToken(ctx context.Context, token string) (*Session, error)
}

type contextKey string

const (
	userIDKey    contextKey = "user_id"
	sessionIDKey contextKey = "session_id"
)

type Middleware struct {
	sessionValidator SessionValidator
}

func NewAuthMiddleware(validator SessionValidator) *Middleware {
	return &Middleware{
		sessionValidator: validator,
	}
}

func (m *Middleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		parts := strings.SplitN(header, " ", 2)

		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
			response.Write(w, http.StatusUnauthorized, "invalid authorization header")
			return
		}

		session, err := m.sessionValidator.ValidateAccessToken(r.Context(), parts[1])
		if err != nil {
			response.Write(w, http.StatusUnauthorized, "authentication failed")
			return
		}

		ctx := context.WithValue(r.Context(), userIDKey, session.UserID)
		ctx = context.WithValue(ctx, sessionIDKey, session.SessionID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func UserID(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(userIDKey).(string)
	return id, ok
}

func SessionID(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(sessionIDKey).(string)
	return id, ok
}
