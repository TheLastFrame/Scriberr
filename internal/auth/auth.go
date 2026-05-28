package auth

import (
	"errors"
	"time"

	"scriberr/internal/models"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// AuthService handles authentication operations
type AuthService struct {
	jwtSecret []byte
	oidc      *oidcVerifier
}

// NewAuthService creates a new authentication service
func NewAuthService(jwtSecret string) *AuthService {
	verifier, _ := newOIDCVerifier(OIDCConfig{})
	return &AuthService{
		jwtSecret: []byte(jwtSecret),
		oidc:      verifier,
	}
}

// NewAuthServiceWithOIDC creates an authentication service with optional OIDC token validation.
func NewAuthServiceWithOIDC(jwtSecret string, oidcConfig OIDCConfig) (*AuthService, error) {
	verifier, err := newOIDCVerifier(oidcConfig)
	if err != nil {
		return nil, err
	}
	return &AuthService{
		jwtSecret: []byte(jwtSecret),
		oidc:      verifier,
	}, nil
}

// Claims represents JWT claims
type Claims struct {
	UserID      uint   `json:"user_id"`
	Username    string `json:"username"`
	IsAdmin     bool   `json:"is_admin"`
	OIDCSubject string `json:"oidc_subject,omitempty"`
	OIDCEmail   string `json:"oidc_email,omitempty"`
	OIDCIssuer  string `json:"oidc_issuer,omitempty"`
	jwt.RegisteredClaims
}

// GenerateToken generates a JWT token for a user
func (as *AuthService) GenerateToken(user *models.User) (string, error) {
	claims := &Claims{
		UserID:   user.ID,
		Username: user.Username,
		IsAdmin:  user.IsAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(as.jwtSecret)
}

// GenerateLongLivedToken generates a JWT token for a user that expires in 1 year
func (as *AuthService) GenerateLongLivedToken(user *models.User) (string, error) {
	claims := &Claims{
		UserID:   user.ID,
		Username: user.Username,
		IsAdmin:  user.IsAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(365 * 24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(as.jwtSecret)
}

// ValidateToken validates a JWT token and returns claims
func (as *AuthService) ValidateToken(tokenString string) (*Claims, error) {
	if as.oidc != nil && as.oidc.enabled {
		if claims, err := as.oidc.validate(tokenString); err == nil {
			return claims, nil
		}
	}

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return as.jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

// HashPassword hashes a password using bcrypt
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// CheckPassword checks if a password matches its hash
func CheckPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
