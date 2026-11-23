package handlers

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/roomies/backend/internal/middleware"
	"github.com/roomies/backend/internal/models"
	"github.com/roomies/backend/internal/oidcauth"
	"github.com/roomies/backend/internal/repository"
)

const (
	defaultSessionTTL    = 8 * time.Hour
	oauthTransactionTTL  = 10 * time.Minute
	oauthStateCookie     = "roomies_oauth_state"
	oauthVerifierCookie  = "roomies_oauth_verifier"
	oauthNonceCookie     = "roomies_oauth_nonce"
	nativeStateCookie    = "roomies_native_state"
	nativeVerifierCookie = "roomies_native_verifier"
	nativeNonceCookie    = "roomies_native_nonce"
	nativeChallenge      = "roomies_native_challenge"
	defaultCallbackLimit = 15
	appCodeTTL           = 2 * time.Minute

	oidcCallbackPath       = "/api/auth/oidc/callback"
	oidcNativeCallbackPath = "/api/auth/oidc/native/callback"
	nativeAppRedirect      = "app.roomies.roomies://oidc"
	// webLandingPath is where the browser lands after web sign-in.
	webLandingPath = "/app/"
)

// Sign-in failure codes sent to the web app (auth_error) and the Android app
// (error). Provider text is never echoed.
const (
	authErrorFailed          = "failed"
	authErrorEmailUnverified = "email_unverified"
	authErrorEmailInUse      = "email_in_use"
	authErrorProvider        = "provider"
)

type oidcCookies struct{ state, verifier, nonce string }

var (
	webOIDCCookies    = oidcCookies{oauthStateCookie, oauthVerifierCookie, oauthNonceCookie}
	nativeOIDCCookies = oidcCookies{nativeStateCookie, nativeVerifierCookie, nativeNonceCookie}
)

type AuthHandler struct {
	userRepo      *repository.UserRepository
	jwtSecret     string
	oidc          *oidcauth.Client
	publicBaseURL string
	limiter       *middleware.WindowLimiter
	callbackLimit int
	nativeEnabled bool
	sessionTTL    time.Duration
	appCodes      *appCodeStore
}

func NewAuthHandler(userRepo *repository.UserRepository, jwtSecret string, oidc *oidcauth.Client) *AuthHandler {
	return &AuthHandler{
		userRepo:      userRepo,
		jwtSecret:     jwtSecret,
		oidc:          oidc,
		limiter:       middleware.NewWindowLimiter(time.Minute),
		callbackLimit: defaultCallbackLimit,
		sessionTTL:    defaultSessionTTL,
		appCodes:      &appCodeStore{grants: map[string]appCodeGrant{}},
	}
}

// SetSessionTTL sets the access-token and session-cookie lifetime.
func (h *AuthHandler) SetSessionTTL(ttl time.Duration) {
	if ttl > 0 {
		h.sessionTTL = ttl
	}
}

// SetPublicBaseURL sets the origin used for OIDC redirect URIs and controls
// the Secure flag on session cookies. HTTPS origins always mark cookies
// Secure, including when TLS terminates at the proxy.
func (h *AuthHandler) SetPublicBaseURL(base string) {
	h.publicBaseURL = strings.TrimRight(strings.TrimSpace(base), "/")
}

// SetRateLimit overrides the per-IP budget for the OIDC callbacks and the
// native code exchange.
func (h *AuthHandler) SetRateLimit(limit int) {
	h.callbackLimit = limit
}

// SetNativeEnabled turns on Android sign-in. Its custom-scheme callback can be
// intercepted by another installed app claiming the same scheme, so it is
// off unless the operator opts in.
func (h *AuthHandler) SetNativeEnabled(enabled bool) {
	h.nativeEnabled = enabled
}

func (h *AuthHandler) Config(w http.ResponseWriter, r *http.Request) {
	name := ""
	if h.oidc != nil {
		name = h.oidc.Name
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"oidc":        h.oidc.Enabled(),
		"oidc_name":   name,
		"oidc_native": h.oidc.Enabled() && h.nativeEnabled,
	})
}

// nativeDisabled answers 404 for the Android routes when they are off.
func (h *AuthHandler) nativeDisabled(w http.ResponseWriter) bool {
	if h.nativeEnabled {
		return false
	}
	writeJSON(w, http.StatusNotFound, models.ErrorResponse{Error: "not found"})
	return true
}

func (h *AuthHandler) oidcDisabled(w http.ResponseWriter) bool {
	if h.oidc.Enabled() {
		return false
	}
	writeJSON(w, http.StatusServiceUnavailable, models.ErrorResponse{Error: "OpenID Connect is not configured"})
	return true
}

// OIDCAuthorize starts web sign-in: it returns the provider URL and keeps
// state, PKCE verifier, and nonce in short-lived HttpOnly cookies.
func (h *AuthHandler) OIDCAuthorize(w http.ResponseWriter, r *http.Request) {
	if h.oidcDisabled(w) {
		return
	}
	authorizationURL, ok := h.beginOIDC(w, r, webOIDCCookies, oidcCallbackPath, false)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"url": authorizationURL})
}

// OIDCCallback finishes web sign-in on the provider redirect, sets the
// session cookies, and sends the browser back to the app.
func (h *AuthHandler) OIDCCallback(w http.ResponseWriter, r *http.Request) {
	if h.oidcDisabled(w) {
		return
	}
	if !h.allow(w, r, "oidc_callback", h.callbackLimit) {
		return
	}
	user, idToken, failure := h.completeOIDC(w, r, webOIDCCookies, oidcCallbackPath)
	if failure == "" {
		token, err := h.generateToken(r.Context(), user, idToken)
		if err != nil {
			failure = authErrorFailed
		} else {
			h.setSessionCookies(w, r, token)
		}
	}
	target := h.publicBaseURL + webLandingPath
	if failure != "" {
		target += "?auth_error=" + failure
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// OIDCNativeStart starts Android sign-in in a browser tab. The server stays
// the OIDC client; the app proves itself later with its own PKCE verifier.
func (h *AuthHandler) OIDCNativeStart(w http.ResponseWriter, r *http.Request) {
	if h.nativeDisabled(w) || h.oidcDisabled(w) {
		return
	}
	appChallenge := r.URL.Query().Get("app_challenge")
	if !validPKCEChallenge(appChallenge) {
		writeJSON(w, http.StatusBadRequest, models.ErrorResponse{Error: "app_challenge must be an S256 PKCE challenge"})
		return
	}
	// Always prompt=login: another app could claim the redirect scheme and
	// start its own transaction, which an existing provider session would
	// otherwise grant silently.
	authorizationURL, ok := h.beginOIDC(w, r, nativeOIDCCookies, oidcNativeCallbackPath, true)
	if !ok {
		return
	}
	setCookie(w, h.cookieName(nativeChallenge), appChallenge, int(oauthTransactionTTL.Seconds()), true, h.secureCookie(r))
	http.Redirect(w, r, authorizationURL, http.StatusFound)
}

// OIDCNativeCallback finishes Android sign-in and hands the app a short-lived,
// single-use code bound to its PKCE challenge.
func (h *AuthHandler) OIDCNativeCallback(w http.ResponseWriter, r *http.Request) {
	if h.nativeDisabled(w) || h.oidcDisabled(w) {
		return
	}
	if !h.allow(w, r, "oidc_native_callback", h.callbackLimit) {
		return
	}
	challengeCookie, err := r.Cookie(h.cookieName(nativeChallenge))
	clearCookie(w, h.cookieName(nativeChallenge), true, h.secureCookie(r))
	var user *models.User
	var idToken, failure string
	if err != nil || !validPKCEChallenge(challengeCookie.Value) {
		h.clearOIDCCookies(w, r, nativeOIDCCookies)
		failure = authErrorFailed
	} else {
		user, idToken, failure = h.completeOIDC(w, r, nativeOIDCCookies, oidcNativeCallbackPath)
	}
	if failure == "" {
		code, err := h.appCodes.issue(appCodeGrant{userID: user.ID, challenge: challengeCookie.Value, idToken: idToken})
		if err == nil {
			http.Redirect(w, r, nativeAppRedirect+"?code="+url.QueryEscape(code), http.StatusFound)
			return
		}
		failure = authErrorFailed
	}
	http.Redirect(w, r, nativeAppRedirect+"?error="+failure, http.StatusFound)
}

type oidcExchangeRequest struct {
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
}

// OIDCExchange trades the app code and the app's PKCE verifier for a session.
func (h *AuthHandler) OIDCExchange(w http.ResponseWriter, r *http.Request) {
	if h.nativeDisabled(w) || h.oidcDisabled(w) {
		return
	}
	if !h.allow(w, r, "oidc_exchange", h.callbackLimit) {
		return
	}
	var req oidcExchangeRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, models.ErrorResponse{Error: "invalid request body"})
		return
	}
	grant, ok := h.appCodes.consume(strings.TrimSpace(req.Code))
	if !ok || req.CodeVerifier == "" || !fixedEqual(pkceChallenge(req.CodeVerifier), grant.challenge) {
		writeJSON(w, http.StatusUnauthorized, models.ErrorResponse{Error: "authentication failed"})
		return
	}
	user, err := h.userRepo.GetByID(r.Context(), grant.userID)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, models.ErrorResponse{Error: "authentication failed"})
		return
	}
	h.finishAuthWithSession(w, r, user, http.StatusOK, grant.idToken)
}

// beginOIDC stores a fresh state, verifier, and nonce in cookies and returns
// the provider authorization URL. It writes the error response itself.
func (h *AuthHandler) beginOIDC(w http.ResponseWriter, r *http.Request, names oidcCookies, callbackPath string, forceLogin bool) (string, bool) {
	state, verifier, challenge, err := newOAuthTransaction()
	nonce, nonceErr := randomURLToken()
	if err != nil || nonceErr != nil {
		writeJSON(w, http.StatusInternalServerError, models.ErrorResponse{Error: "failed to start sign-in"})
		return "", false
	}
	authorizationURL, err := h.oidc.AuthURL(r.Context(), h.publicBaseURL+callbackPath, state, challenge, nonce, forceLogin)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, models.ErrorResponse{Error: "sign-in provider unavailable"})
		return "", false
	}
	secure := h.secureCookie(r)
	maxAge := int(oauthTransactionTTL.Seconds())
	setCookie(w, h.cookieName(names.state), state, maxAge, true, secure)
	setCookie(w, h.cookieName(names.verifier), verifier, maxAge, true, secure)
	setCookie(w, h.cookieName(names.nonce), nonce, maxAge, true, secure)
	return authorizationURL, true
}

// completeOIDC consumes the transaction cookies, redeems the code, and
// upserts the verified user. On failure it returns one of the authError codes.
func (h *AuthHandler) completeOIDC(w http.ResponseWriter, r *http.Request, names oidcCookies, callbackPath string) (*models.User, string, string) {
	query := r.URL.Query()
	stateCookie, stateErr := r.Cookie(h.cookieName(names.state))
	verifierCookie, verifierErr := r.Cookie(h.cookieName(names.verifier))
	nonceCookie, nonceErr := r.Cookie(h.cookieName(names.nonce))
	h.clearOIDCCookies(w, r, names)
	if query.Get("error") != "" {
		return nil, "", authErrorProvider
	}
	code, state := query.Get("code"), query.Get("state")
	if code == "" || state == "" || stateErr != nil || verifierErr != nil || nonceErr != nil ||
		!fixedEqual(state, stateCookie.Value) || verifierCookie.Value == "" || nonceCookie.Value == "" {
		return nil, "", authErrorFailed
	}
	identity, err := h.oidc.Exchange(r.Context(), h.publicBaseURL+callbackPath, code, verifierCookie.Value, nonceCookie.Value)
	if err != nil {
		return nil, "", authErrorFailed
	}
	// Invitations bind to the email, so it must be one the provider verified.
	if !identity.EmailVerified {
		return nil, "", authErrorEmailUnverified
	}
	email := strings.ToLower(strings.TrimSpace(identity.Email))
	name := strings.TrimSpace(identity.Name)
	if name == "" {
		name = email
	}
	user, err := h.userRepo.UpsertFromOIDC(r.Context(), identity.Issuer, identity.Subject, email, name)
	if errors.Is(err, repository.ErrEmailInUse) {
		return nil, "", authErrorEmailInUse
	}
	if err != nil {
		return nil, "", authErrorFailed
	}
	return user, identity.IDToken, ""
}

func (h *AuthHandler) clearOIDCCookies(w http.ResponseWriter, r *http.Request, names oidcCookies) {
	secure := h.secureCookie(r)
	clearCookie(w, h.cookieName(names.state), true, secure)
	clearCookie(w, h.cookieName(names.verifier), true, secure)
	clearCookie(w, h.cookieName(names.nonce), true, secure)
}

// cookieName gives HttpOnly auth cookies the __Host- prefix on an https
// deployment so a sibling subdomain cannot plant them.
func (h *AuthHandler) cookieName(name string) string {
	return middleware.CookieName(name, oidcauth.IsHTTPS(h.publicBaseURL))
}

// SessionCookieName is this deployment's session cookie name; the session
// middleware must read exactly this name.
func (h *AuthHandler) SessionCookieName() string {
	return h.cookieName(middleware.SessionCookieName)
}

// Logout clears the Roomies session. When the provider supports it, it also
// returns the provider logout URL so the client can end that session too;
// otherwise the next "Sign in" would silently reuse the old account.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	logoutURL := ""
	// Revoke the token itself: clearing the cookie alone would leave a copied
	// token (or a native app's bearer) usable until it expires. The logout
	// hint is taken in the same transaction, so a failure leaves both for a
	// retry.
	if claims := h.sessionClaims(r); claims != nil {
		jti, _ := claims["jti"].(string)
		if exp, err := claims.GetExpirationTime(); err == nil && exp != nil && jti != "" {
			issuer, idTokenHint, err := h.userRepo.EndSession(r.Context(), jti, exp.Time)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, models.ErrorResponse{Error: "failed to end session"})
				return
			}
			// A hint minted by another issuer (the configuration changed
			// since sign-in) must not be sent to the current provider.
			if h.oidc.Enabled() && issuer == h.oidc.Issuer {
				logoutURL = h.oidc.LogoutURL(r.Context(), idTokenHint, h.publicBaseURL+webLandingPath)
			}
		}
	}
	secure := h.secureCookie(r)
	clearCookie(w, h.SessionCookieName(), true, secure)
	clearCookie(w, middleware.SessionHintCookieName, false, secure)
	if logoutURL != "" {
		writeJSON(w, http.StatusOK, map[string]string{"logout_url": logoutURL})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// sessionClaims returns the claims of the request's still-valid Roomies
// session token, or nil for missing, expired, or forged tokens.
func (h *AuthHandler) sessionClaims(r *http.Request) jwt.MapClaims {
	raw, ok := middleware.SessionToken(r, h.SessionCookieName())
	if !ok {
		return nil
	}
	claims, err := middleware.ParseSessionClaims(raw, h.jwtSecret)
	if err != nil {
		return nil
	}
	return claims
}

func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	user, err := h.userRepo.GetByID(r.Context(), userID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, models.ErrorResponse{Error: "user not found"})
		return
	}
	writeJSON(w, http.StatusOK, user)
}

// generateToken signs a session for user. The provider ID token, if any, is
// stored server-side under the session id as the logout hint, never in the
// token itself.
func (h *AuthHandler) generateToken(ctx context.Context, user *models.User, idToken string) (string, error) {
	jti, err := randomURLToken()
	if err != nil {
		return "", err
	}
	expires := time.Now().Add(h.sessionTTL)
	if idToken != "" {
		// go-oidc verified the token's iss equals the configured issuer.
		if err := h.userRepo.SaveSessionIDToken(ctx, jti, h.oidc.Issuer, idToken, expires); err != nil {
			return "", err
		}
	}
	claims := jwt.MapClaims{
		"user_id": user.ID,
		"email":   user.Email,
		"jti":     jti,
		"exp":     expires.Unix(),
		"iat":     time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(h.jwtSecret))
}

func (h *AuthHandler) finishAuthWithSession(w http.ResponseWriter, r *http.Request, user *models.User, status int, idToken string) {
	token, err := h.generateToken(r.Context(), user, idToken)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, models.ErrorResponse{Error: "failed to generate token"})
		return
	}
	h.setSessionCookies(w, r, token)
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Roomies-Client")), "web") {
		writeJSON(w, status, struct {
			User models.User `json:"user"`
		}{User: *user})
		return
	}
	writeJSON(w, status, models.AuthResponse{Token: token, User: *user})
}

func (h *AuthHandler) setSessionCookies(w http.ResponseWriter, r *http.Request, token string) {
	secure := h.secureCookie(r)
	maxAge := int(h.sessionTTL.Seconds())
	setCookie(w, h.SessionCookieName(), token, maxAge, true, secure)
	setCookie(w, middleware.SessionHintCookieName, "1", maxAge, false, secure)
}

func (h *AuthHandler) allow(w http.ResponseWriter, r *http.Request, route string, limit int) bool {
	if h.limiter == nil || h.limiter.Allow(route+"|"+rateLimitIP(r), limit) {
		return true
	}
	w.Header().Set("Retry-After", "60")
	writeJSON(w, http.StatusTooManyRequests, models.ErrorResponse{Error: "too many requests"})
	return false
}

func (h *AuthHandler) secureCookie(r *http.Request) bool {
	if r != nil && r.TLS != nil {
		return true
	}
	if r != nil && strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https") {
		return true
	}
	parsed, err := url.Parse(h.publicBaseURL)
	return err == nil && strings.EqualFold(parsed.Scheme, "https")
}

func newOAuthTransaction() (state, verifier, challenge string, err error) {
	state, err = randomURLToken()
	if err != nil {
		return "", "", "", err
	}
	verifier, err = randomURLToken()
	if err != nil {
		return "", "", "", err
	}
	return state, verifier, pkceChallenge(verifier), nil
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// validPKCEChallenge accepts an unpadded base64url SHA-256 digest.
func validPKCEChallenge(challenge string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(challenge)
	return err == nil && len(decoded) == sha256.Size
}

// appCodeGrant is what a native app code redeems for. Codes live in memory:
// they are single-use and expire after appCodeTTL.
type appCodeGrant struct {
	userID, challenge, idToken string
	expires                    time.Time
}

type appCodeStore struct {
	mu     sync.Mutex
	grants map[string]appCodeGrant
}

func (s *appCodeStore) issue(grant appCodeGrant) (string, error) {
	code, err := randomURLToken()
	if err != nil {
		return "", err
	}
	now := time.Now()
	grant.expires = now.Add(appCodeTTL)
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, existing := range s.grants {
		if now.After(existing.expires) {
			delete(s.grants, key)
		}
	}
	s.grants[code] = grant
	return code, nil
}

// consume removes the code on any attempt, so a guessed or replayed code
// never gets a second try.
func (s *appCodeStore) consume(code string) (appCodeGrant, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	grant, ok := s.grants[code]
	delete(s.grants, code)
	return grant, ok && time.Now().Before(grant.expires)
}

func randomURLToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func fixedEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func setCookie(w http.ResponseWriter, name, value string, maxAge int, httpOnly, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: httpOnly,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearCookie(w http.ResponseWriter, name string, httpOnly, secure bool) {
	setCookie(w, name, "", -1, httpOnly, secure)
}

// rateLimitIP uses the last X-Forwarded-For hop. Caddy replaces that header
// with the connecting client, so a browser cannot pick its own bucket.
func rateLimitIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		if ip := strings.TrimSpace(parts[len(parts)-1]); ip != "" {
			return ip
		}
	}
	return remoteIP(r)
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || host == "" {
		return r.RemoteAddr
	}
	return host
}
