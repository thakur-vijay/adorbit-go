package middleware

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/thakur-vijay/adorbit-go/response"
)

type JWTClaims struct {
	UserID string `json:"user_id"`
	jwtlib.RegisteredClaims
}

type JWTMiddleware struct {
	publicKey *rsa.PublicKey
	issuer    string
}

func NewJWTMiddleware(publicKeyPEM, issuer string) (*JWTMiddleware, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, errors.New("failed to decode public key PEM")
	}

	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	publicKey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not RSA")
	}

	return &JWTMiddleware{
		publicKey: publicKey,
		issuer:    issuer,
	}, nil
}

func (m *JWTMiddleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		parts := strings.SplitN(header, " ", 2)

		if len(parts) != 2 ||
			!strings.EqualFold(parts[0], "Bearer") ||
			strings.TrimSpace(parts[1]) == "" {
			response.Write(w, http.StatusUnauthorized, "invalid authorization header")
			return
		}

		claims := &JWTClaims{}

		token, err := jwtlib.ParseWithClaims(
			strings.TrimSpace(parts[1]),
			claims,
			func(token *jwtlib.Token) (any, error) {
				if token.Method != jwtlib.SigningMethodRS256 {
					return nil, errors.New("unexpected signing method")
				}
				return m.publicKey, nil
			},
			jwtlib.WithIssuer(m.issuer),
			jwtlib.WithExpirationRequired(),
			jwtlib.WithIssuedAt(),
			jwtlib.WithLeeway(30*time.Second),
		)

		if err != nil || token == nil || !token.Valid ||
			claims.UserID == "" || claims.Subject != claims.UserID {
			response.Write(w, http.StatusUnauthorized, "authentication failed")
			return
		}

		ctx := context.WithValue(r.Context(), userIDKey, claims.UserID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
