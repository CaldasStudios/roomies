// Package oidcauth signs people in through any OpenID Connect provider using
// the authorization code flow with PKCE, state, and nonce.
package oidcauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// ErrUnavailable means the issuer could not be discovered; it is retried on
// the next request instead of failing server startup.
var ErrUnavailable = errors.New("oidc discovery unavailable")

// httpClient bounds every provider call (discovery, JWKS, token, userinfo).
var httpClient = &http.Client{Timeout: 15 * time.Second}

func withClient(ctx context.Context) context.Context {
	return oidc.ClientContext(ctx, httpClient)
}

// Identity is the verified result of a sign-in.
type Identity struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	// IDToken is the raw ID token, kept only as the id_token_hint for logout.
	IDToken string
}

// Client lazily discovers the issuer; discovery failures are not cached.
type Client struct {
	Issuer, ClientID, ClientSecret string
	// Name labels the sign-in button.
	Name string

	mu       sync.Mutex
	provider *oidc.Provider
}

func (c *Client) Enabled() bool {
	return c != nil && strings.TrimSpace(c.Issuer) != "" && strings.TrimSpace(c.ClientID) != ""
}

func (c *Client) discover(ctx context.Context) (*oidc.Provider, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.provider != nil {
		return c.provider, nil
	}
	p, err := oidc.NewProvider(withClient(ctx), c.Issuer)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	c.provider = p
	return p, nil
}

func (c *Client) config(p *oidc.Provider, redirect string) oauth2.Config {
	endpoint := p.Endpoint()
	endpoint.AuthStyle = oauth2.AuthStyleInHeader
	if c.ClientSecret == "" {
		// Public client: send client_id in the body, no empty Basic auth.
		endpoint.AuthStyle = oauth2.AuthStyleInParams
	}
	return oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURL:  redirect,
		Endpoint:     endpoint,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
}

// AuthURL returns the provider authorization URL for one sign-in attempt.
func (c *Client) AuthURL(ctx context.Context, redirect, state, challenge, nonce string) (string, error) {
	p, err := c.discover(ctx)
	if err != nil {
		return "", err
	}
	cfg := c.config(p, redirect)
	return cfg.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oidc.Nonce(nonce),
	), nil
}

// Exchange redeems code, verifies the ID token (signature, issuer, audience,
// expiry, nonce) and fills email, email_verified, and name from userinfo when
// the ID token omits them.
func (c *Client) Exchange(ctx context.Context, redirect, code, verifier, nonce string) (*Identity, error) {
	p, err := c.discover(ctx)
	if err != nil {
		return nil, err
	}
	ctx = withClient(ctx)
	cfg := c.config(p, redirect)
	token, err := cfg.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", verifier))
	if err != nil {
		return nil, err
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok || raw == "" {
		return nil, errors.New("missing id token")
	}
	id, err := p.Verifier(&oidc.Config{ClientID: c.ClientID}).Verify(ctx, raw)
	if err != nil {
		return nil, err
	}
	if id.Nonce == "" || id.Nonce != nonce {
		return nil, errors.New("invalid nonce")
	}
	var claims struct {
		Email         string `json:"email"`
		EmailVerified *bool  `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err := id.Claims(&claims); err != nil {
		return nil, err
	}
	identity := &Identity{Subject: id.Subject, Email: claims.Email, Name: claims.Name, IDToken: raw}
	if claims.EmailVerified != nil {
		identity.EmailVerified = *claims.EmailVerified
	}
	if claims.Email == "" || claims.EmailVerified == nil {
		// The access token never leaves HTTPS for a plain-HTTP userinfo URL.
		if strings.HasPrefix(c.Issuer, "https://") && !strings.HasPrefix(p.UserInfoEndpoint(), "https://") {
			return nil, errors.New("userinfo endpoint is not https")
		}
		info, err := p.UserInfo(ctx, oauth2.StaticTokenSource(token))
		if err != nil {
			return nil, err
		}
		if info.Subject != id.Subject {
			return nil, errors.New("userinfo subject mismatch")
		}
		var profile struct {
			Name string `json:"name"`
		}
		if err := info.Claims(&profile); err != nil {
			return nil, err
		}
		identity.Email, identity.EmailVerified = info.Email, info.EmailVerified
		if profile.Name != "" {
			identity.Name = profile.Name
		}
	}
	if identity.Subject == "" || identity.Email == "" {
		return nil, errors.New("missing identity")
	}
	return identity, nil
}

// LogoutURL builds the RP-initiated logout URL, or "" when the provider has
// no end_session_endpoint, discovery fails, or there is no ID token hint.
func (c *Client) LogoutURL(ctx context.Context, idTokenHint, postLogoutRedirect string) string {
	if !c.Enabled() || idTokenHint == "" {
		return ""
	}
	p, err := c.discover(ctx)
	if err != nil {
		return ""
	}
	var meta struct {
		EndSession string `json:"end_session_endpoint"`
	}
	if err := p.Claims(&meta); err != nil || meta.EndSession == "" {
		return ""
	}
	endSession, err := url.Parse(meta.EndSession)
	if err != nil {
		return ""
	}
	query := endSession.Query()
	query.Set("id_token_hint", idTokenHint)
	query.Set("client_id", c.ClientID)
	if postLogoutRedirect != "" {
		query.Set("post_logout_redirect_uri", postLogoutRedirect)
	}
	endSession.RawQuery = query.Encode()
	return endSession.String()
}
