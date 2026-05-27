package auth

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// OIDCConfig stores generic OIDC verifier configuration.
type OIDCConfig struct {
	Enabled       bool
	IssuerURL     string
	Audience      string
	JWKSURL       string
	ClientID      string
	UsernameClaim string
}

type oidcVerifier struct {
	enabled bool
	issuer  string
	aud     string
}

type oidcClaims struct {
	Username string `json:"preferred_username"`
	Email    string `json:"email"`
	Sub      string `json:"sub"`
	jwt.RegisteredClaims
}

func newOIDCVerifier(cfg OIDCConfig) (*oidcVerifier, error) {
	if !cfg.Enabled {
		return &oidcVerifier{enabled: false}, nil
	}
	if cfg.IssuerURL == "" {
		return nil, fmt.Errorf("oidc issuer url is required when oidc is enabled")
	}

	aud := cfg.Audience
	if aud == "" {
		aud = cfg.ClientID
	}

	return &oidcVerifier{
		enabled: true,
		issuer:  cfg.IssuerURL,
		aud:     aud,
	}, nil
}

func (v *oidcVerifier) validate(tokenString string) (*Claims, error) {
	if !v.enabled {
		return nil, fmt.Errorf("oidc disabled")
	}

	parser := jwt.NewParser()
	claims := &oidcClaims{}
	_, _, err := parser.ParseUnverified(tokenString, claims)
	if err != nil {
		return nil, err
	}
	if claims.Issuer != v.issuer {
		return nil, fmt.Errorf("invalid issuer")
	}
	if v.aud != "" {
		matched := false
		for _, aud := range claims.Audience {
			if aud == v.aud {
				matched = true
				break
			}
		}
		if !matched {
			return nil, fmt.Errorf("invalid audience")
		}
	}

	return nil, fmt.Errorf("oidc token signature validation not yet configured; set up jwks verifier in follow-up PR")
}
