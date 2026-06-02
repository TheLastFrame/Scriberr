package auth

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
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
	AdminRole     string
	RoleClaims    string
}

type oidcDiscoveryDocument struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

type oidcVerifier struct {
	enabled    bool
	issuer     string
	aud        string
	jwksURL    string
	adminRole  string
	roleClaims []string
	client     *http.Client
	mu         sync.RWMutex
	keys       map[string]interface{}
	lastSync   time.Time
}

type oidcRoleAccess struct {
	Roles []string `json:"roles"`
}

type oidcClaims struct {
	Username       string                    `json:"preferred_username"`
	Email          string                    `json:"email"`
	Sub            string                    `json:"sub"`
	Roles          []string                  `json:"roles"`
	Groups         []string                  `json:"groups"`
	RealmAccess    oidcRoleAccess            `json:"realm_access"`
	ResourceAccess map[string]oidcRoleAccess `json:"resource_access"`
	jwt.RegisteredClaims
}

type jwkSet struct {
	Keys []struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		Use string `json:"use"`
		Alg string `json:"alg"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
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
	adminRole := strings.TrimSpace(cfg.AdminRole)
	if adminRole == "" {
		adminRole = "admin"
	}
	roleClaims := parseOIDCRoleClaims(cfg.RoleClaims)

	return &oidcVerifier{
		enabled:    true,
		issuer:     strings.TrimRight(cfg.IssuerURL, "/"),
		aud:        aud,
		jwksURL:    strings.TrimSpace(cfg.JWKSURL),
		adminRole:  adminRole,
		roleClaims: roleClaims,
		client:     &http.Client{Timeout: 8 * time.Second},
		keys:       map[string]interface{}{},
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
	if err := v.ensureKeys(); err != nil {
		return nil, err
	}
	claims := &oidcClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		if !strings.HasPrefix(t.Method.Alg(), "RS") {
			return nil, fmt.Errorf("unsupported oidc signing algorithm: %s", t.Method.Alg())
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("missing kid")
		}
		v.mu.RLock()
		key := v.keys[kid]
		v.mu.RUnlock()
		if key == nil {
			_ = v.ensureKeys()
			v.mu.RLock()
			key = v.keys[kid]
			v.mu.RUnlock()
			if key == nil {
				return nil, fmt.Errorf("no matching jwk for kid")
			}
		}
		return key, nil
	})
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("oidc token validation failed: %w", err)
	}
	if strings.TrimRight(claims.Issuer, "/") != v.issuer {
		return nil, fmt.Errorf("invalid issuer")
	}
	if v.aud != "" {
		matched := false
		for _, a := range claims.Audience {
			if a == v.aud {
				matched = true
				break
			}
		}
		if !matched {
			return nil, fmt.Errorf("invalid audience")
		}
	}
	return &Claims{
		Username:         claims.Username,
		IsAdmin:          claims.hasRole(v.adminRole, v.roleClaims),
		OIDCSubject:      claims.Sub,
		OIDCEmail:        claims.Email,
		OIDCIssuer:       claims.Issuer,
		RegisteredClaims: claims.RegisteredClaims,
	}, nil
}

func (c *oidcClaims) hasRole(roleName string, roleClaims []string) bool {
	for _, claim := range roleClaims {
		switch claim {
		case "roles":
			if hasOIDCRole(c.Roles, roleName) {
				return true
			}
		case "groups":
			if hasOIDCRole(c.Groups, roleName) {
				return true
			}
		case "realm_access.roles":
			if hasOIDCRole(c.RealmAccess.Roles, roleName) {
				return true
			}
		case "resource_access.*.roles":
			for _, access := range c.ResourceAccess {
				if hasOIDCRole(access.Roles, roleName) {
					return true
				}
			}
		default:
			if strings.HasPrefix(claim, "resource_access.") && strings.HasSuffix(claim, ".roles") {
				clientID := strings.TrimSuffix(strings.TrimPrefix(claim, "resource_access."), ".roles")
				if access, ok := c.ResourceAccess[clientID]; ok && hasOIDCRole(access.Roles, roleName) {
					return true
				}
			}
		}
	}
	return false
}

func parseOIDCRoleClaims(value string) []string {
	if strings.TrimSpace(value) == "" {
		return []string{"roles", "groups", "realm_access.roles", "resource_access.*.roles"}
	}
	parts := strings.Split(value, ",")
	claims := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		claim := strings.TrimSpace(part)
		if claim == "" {
			continue
		}
		if _, ok := seen[claim]; ok {
			continue
		}
		seen[claim] = struct{}{}
		claims = append(claims, claim)
	}
	return claims
}

func hasOIDCRole(roles []string, roleName string) bool {
	roleName = strings.Trim(strings.TrimSpace(roleName), "/")
	if roleName == "" {
		return false
	}
	for _, role := range roles {
		role = strings.Trim(strings.TrimSpace(role), "/")
		if strings.EqualFold(role, roleName) {
			return true
		}
	}
	return false
}

func (v *oidcVerifier) ensureKeys() error {
	v.mu.RLock()
	if time.Since(v.lastSync) < 10*time.Minute && len(v.keys) > 0 {
		v.mu.RUnlock()
		return nil
	}
	v.mu.RUnlock()
	jwksURL := v.jwksURL
	if jwksURL == "" {
		discoveryURL := strings.TrimRight(v.issuer, "/") + "/.well-known/openid-configuration"
		resp, err := v.client.Get(discoveryURL) //nolint:gosec
		if err != nil {
			return fmt.Errorf("oidc discovery request failed: %w", err)
		}
		defer resp.Body.Close()
		var doc oidcDiscoveryDocument
		if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
			return fmt.Errorf("failed to decode oidc discovery document: %w", err)
		}
		jwksURL = doc.JWKSURI
	}
	resp, err := v.client.Get(jwksURL) //nolint:gosec
	if err != nil {
		return fmt.Errorf("failed to fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	var set jwkSet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return fmt.Errorf("failed to decode jwks: %w", err)
	}
	keys := map[string]interface{}{}
	for _, k := range set.Keys {
		if strings.ToUpper(k.Kty) != "RSA" || k.Kid == "" || k.N == "" || k.E == "" {
			continue
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			continue
		}
		n := new(big.Int).SetBytes(nBytes)
		e := new(big.Int).SetBytes(eBytes).Int64()
		keys[k.Kid] = &rsa.PublicKey{N: n, E: int(e)}
	}
	if len(keys) == 0 {
		return fmt.Errorf("no usable rsa keys in jwks")
	}
	v.mu.Lock()
	v.keys = keys
	v.lastSync = time.Now()
	v.mu.Unlock()
	return nil
}
