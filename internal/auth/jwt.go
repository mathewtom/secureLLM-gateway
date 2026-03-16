// Package auth provides JWT token generation, validation, and role-based
// access control for the SecureLLM Gateway.
package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Sentinel errors for token validation failures. Callers can distinguish
// failure modes with errors.Is() while returning generic messages to clients.
var (
	ErrTokenExpired  = errors.New("token has expired")
	ErrInvalidToken  = errors.New("token is invalid")
	ErrInvalidClaims = errors.New("token claims are invalid")
)

// Role represents a user's authorization level for RBAC.
type Role string

const (
	RoleAdmin    Role = "admin"
	RoleUser     Role = "user"
	RoleReadOnly Role = "readonly"
)

// Claims extends jwt.RegisteredClaims with application-specific fields.
// Note: JWT payloads are Base64-encoded, not encrypted — never include
// sensitive data (passwords, card numbers) in claims.
type Claims struct {
	jwt.RegisteredClaims
	Role  Role   `json:"role"`
	Email string `json:"email"`
}

// TokenService handles JWT token creation and validation.
type TokenService struct {
	signingKey []byte
	expiration time.Duration
	issuer     string
}

// NewTokenService creates a TokenService with the given HMAC key and expiration.
func NewTokenService(secret string, expirationMinutes int, issuer string) *TokenService {
	return &TokenService{
		signingKey: []byte(secret),
		expiration: time.Duration(expirationMinutes) * time.Minute,
		issuer:     issuer,
	}
}

// GenerateToken creates a signed HS256 JWT for the given user.
func (ts *TokenService) GenerateToken(userID, email string, role Role) (string, error) {
	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    ts.issuer,
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(now.Add(ts.expiration)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
		Role:  role,
		Email: email,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(ts.signingKey)
}

// ValidateToken parses a JWT string and validates its signature, algorithm,
// expiration, issuer, and role. Returns the claims if all checks pass.
func (ts *TokenService) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(
		tokenString,
		&Claims{},
		func(token *jwt.Token) (interface{}, error) {
			// Reject algorithm switching attacks (e.g., "none", RS256).
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return ts.signingKey, nil
		},
		jwt.WithIssuer(ts.issuer),
		jwt.WithExpirationRequired(),
	)

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidClaims
	}

	if !isValidRole(claims.Role) {
		return nil, fmt.Errorf("%w: unrecognized role %q", ErrInvalidClaims, claims.Role)
	}

	return claims, nil
}

func isValidRole(role Role) bool {
	switch role {
	case RoleAdmin, RoleUser, RoleReadOnly:
		return true
	default:
		return false
	}
}
