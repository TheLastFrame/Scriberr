package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"scriberr/internal/auth"
	"scriberr/internal/models"
	"scriberr/pkg/logger"

	"github.com/gin-gonic/gin"
)

type oidcDiscovery struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

type oidcTokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
}

func randomOIDCString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (h *Handler) getOIDCRedirectURL(c *gin.Context) string {
	if h.config.OIDCRedirectURL != "" {
		return h.config.OIDCRedirectURL
	}
	scheme := "http"
	if c.Request.TLS != nil {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s/api/v1/auth/oidc/callback", scheme, c.Request.Host)
}

func (h *Handler) OIDCStart(c *gin.Context) {
	if !h.config.OIDCEnabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "OIDC is disabled"})
		return
	}
	if h.config.OIDCIssuerURL == "" || h.config.OIDCClientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "OIDC issuer/client config missing"})
		return
	}

	state, err := randomOIDCString(24)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate state"})
		return
	}

	issuer := strings.TrimRight(h.config.OIDCIssuerURL, "/")
	discoURL := issuer + "/.well-known/openid-configuration"
	resp, err := http.Get(discoURL) //nolint:gosec
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to fetch oidc discovery"})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		c.JSON(http.StatusBadGateway, gin.H{"error": "oidc discovery endpoint returned non-2xx"})
		return
	}
	var disco oidcDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&disco); err != nil || disco.AuthorizationEndpoint == "" {
		c.JSON(http.StatusBadGateway, gin.H{"error": "invalid oidc discovery response"})
		return
	}

	redirectURI := h.getOIDCRedirectURL(c)
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", h.config.OIDCClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", "openid profile email")
	q.Set("state", state)
	if h.config.OIDCAudience != "" {
		q.Set("audience", h.config.OIDCAudience)
	}

	secure := h.config.SecureCookies
	if c.Request.TLS == nil && !h.config.IsProduction() {
		secure = false
	}
	c.SetCookie("scriberr_oidc_state", state, int((10 * time.Minute).Seconds()), "/", "", secure, true)
	c.Redirect(http.StatusFound, disco.AuthorizationEndpoint+"?"+q.Encode())
}

func (h *Handler) OIDCCallback(c *gin.Context) {
	state := c.Query("state")
	code := c.Query("code")
	if state == "" || code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing state or code"})
		return
	}
	storedState, err := c.Cookie("scriberr_oidc_state")
	if err != nil || storedState == "" || storedState != state {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid oidc state"})
		return
	}

	issuer := strings.TrimRight(h.config.OIDCIssuerURL, "/")
	discoURL := issuer + "/.well-known/openid-configuration"
	resp, err := http.Get(discoURL) //nolint:gosec
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to fetch oidc discovery"})
		return
	}
	defer resp.Body.Close()
	var disco oidcDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&disco); err != nil || disco.TokenEndpoint == "" {
		c.JSON(http.StatusBadGateway, gin.H{"error": "invalid oidc discovery response"})
		return
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", h.config.OIDCClientID)
	form.Set("redirect_uri", h.getOIDCRedirectURL(c))
	if h.config.OIDCClientSecret != "" {
		form.Set("client_secret", h.config.OIDCClientSecret)
	}
	tokenReq, _ := http.NewRequestWithContext(c.Request.Context(), http.MethodPost, disco.TokenEndpoint, strings.NewReader(form.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenResp, err := http.DefaultClient.Do(tokenReq)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed token exchange"})
		return
	}
	defer tokenResp.Body.Close()
	body, _ := io.ReadAll(tokenResp.Body)
	if tokenResp.StatusCode < 200 || tokenResp.StatusCode >= 300 {
		c.JSON(http.StatusBadGateway, gin.H{"error": "oidc token exchange failed", "details": string(body)})
		return
	}

	var tr oidcTokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "invalid token response"})
		return
	}
	if tr.AccessToken == "" && tr.IDToken == "" {
		c.JSON(http.StatusBadGateway, gin.H{"error": "oidc token response missing token"})
		return
	}

	// For OIDC login identity, prefer ID token first.
	// Access tokens may be opaque/provider-specific and are not guaranteed
	// to be locally verifiable JWTs for this client.
	candidate := tr.IDToken
	if candidate == "" {
		candidate = tr.AccessToken
	}
	claims, err := h.authService.ValidateToken(candidate)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "oidc token validation failed", "details": err.Error()})
		return
	}

	username := claims.Username
	if username == "" {
		if claims.OIDCEmail != "" {
			username = claims.OIDCEmail
		} else if claims.OIDCSubject != "" {
			username = "oidc_" + claims.OIDCSubject
		}
	}
	if username == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unable to derive user identity"})
		return
	}

	logger.Debug("OIDC login claims evaluated",
		"username", username,
		"subject", claims.OIDCSubject,
		"issuer", claims.OIDCIssuer,
		"email_present", claims.OIDCEmail != "",
		"is_admin", claims.IsAdmin,
		"admin_claim", claims.OIDCAdminClaim,
	)

	user, err := h.userRepo.FindByUsername(c.Request.Context(), username)
	if err != nil {
		randomPassword, randErr := randomOIDCString(24)
		if randErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to provision user"})
			return
		}
		pw, hashErr := auth.HashPassword(randomPassword)
		if hashErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to provision user"})
			return
		}
		newUser := &models.User{Username: username, Password: pw, IsAdmin: claims.IsAdmin}
		if err := h.userRepo.Create(c.Request.Context(), newUser); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to provision user"})
			return
		}
		user = newUser
		logger.Debug("OIDC user provisioned", "username", username, "is_admin", user.IsAdmin, "admin_claim", claims.OIDCAdminClaim)
	} else if user.IsAdmin != claims.IsAdmin {
		// Keep OIDC-managed admin status in sync on every OIDC login.
		// If the provider removes the configured admin role, the local user is demoted.
		oldIsAdmin := user.IsAdmin
		user.IsAdmin = claims.IsAdmin
		if err := h.userRepo.Update(c.Request.Context(), user); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update user role"})
			return
		}
		logger.Debug("OIDC user admin state synced", "username", username, "old_is_admin", oldIsAdmin, "new_is_admin", user.IsAdmin, "admin_claim", claims.OIDCAdminClaim)
	}

	jwtToken, err := h.authService.GenerateToken(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate session token"})
		return
	}
	if err := h.issueRefreshToken(c, user.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
		return
	}

	// Set access token cookie for media/subresource requests (audio/video)
	// where Authorization headers are not always present.
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "scriberr_access_token",
		Value:    jwtToken,
		Path:     "/",
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Secure:   h.config.SecureCookies,
		SameSite: http.SameSiteLaxMode,
	})

	if c.Query("format") == "json" {
		c.JSON(http.StatusOK, LoginResponse{Token: jwtToken})
		return
	}
	c.Redirect(http.StatusFound, "/?token="+url.QueryEscape(jwtToken))
}

func (h *Handler) OIDCLogout(c *gin.Context) {
	// Always clear local session first (same behavior as Logout)
	if cookie, err := c.Cookie("scriberr_refresh_token"); err == nil {
		h.revokeRefreshToken(c, cookie)
	}
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "scriberr_refresh_token",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   h.config.SecureCookies,
	})
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "scriberr_access_token",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   h.config.SecureCookies,
	})
	if !h.config.OIDCEnabled || h.config.OIDCIssuerURL == "" {
		return
	}

	issuer := strings.TrimRight(h.config.OIDCIssuerURL, "/")
	discoURL := issuer + "/.well-known/openid-configuration"
	resp, err := http.Get(discoURL) //nolint:gosec
	if err != nil {
		return
	}
	defer resp.Body.Close()
	var disco oidcDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&disco); err != nil || disco.EndSessionEndpoint == "" {
		return
	}

	postLogout := h.config.OIDCPostLogoutRedirectURL
	if postLogout == "" {
		scheme := "http"
		if c.Request.TLS != nil {
			scheme = "https"
		}
		postLogout = fmt.Sprintf("%s://%s/", scheme, c.Request.Host)
	}
	u, err := url.Parse(disco.EndSessionEndpoint)
	if err != nil {
		return
	}
	q := u.Query()
	q.Set("post_logout_redirect_uri", postLogout)
	if h.config.OIDCClientID != "" {
		q.Set("client_id", h.config.OIDCClientID)
	}
	u.RawQuery = q.Encode()
	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully", "redirect_url": u.String()})
}
