package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// OIDCConfig stores generic OIDC verifier configuration.
type OIDCConfig struct {
	Enabled       bool
	IssuerURL     string
	Audience      string
	JWKSURL       string
	ClientID      string
	ClientSecret  string
	UsernameClaim string
}

type oidcDiscoveryDocument struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
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

// ValidateOIDCConnectivity performs a best-effort discovery check.
// It is intended for startup diagnostics and does not validate token signatures.
func ValidateOIDCConnectivity(cfg OIDCConfig) error {
	if !cfg.Enabled {
		return nil
	}
	issuer := strings.TrimRight(cfg.IssuerURL, "/")
	if issuer == "" {
		return fmt.Errorf("oidc issuer url is required when oidc is enabled")
	}
	discoveryURL := issuer + "/.well-known/openid-configuration"
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(discoveryURL) //nolint:gosec
	if err != nil {
		return fmt.Errorf("oidc discovery request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("oidc discovery returned non-2xx status: %d", resp.StatusCode)
	}
	var doc oidcDiscoveryDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("failed to decode oidc discovery document: %w", err)
	}
	if doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" {
		return fmt.Errorf("oidc discovery document missing required endpoints")
	}
	return nil
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
