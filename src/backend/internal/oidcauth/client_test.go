package oidcauth

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEnabledNeedsIssuerAndClientID(t *testing.T) {
	var nilClient *Client
	for _, c := range []*Client{nilClient, {Issuer: "https://id.example"}, {ClientID: "roomies"}} {
		if c.Enabled() {
			t.Fatalf("%#v reported enabled", c)
		}
	}
	if !(&Client{Issuer: "https://id.example", ClientID: "roomies"}).Enabled() {
		t.Fatal("configured client reported disabled")
	}
}

func TestDiscoveryFailureIsRetried(t *testing.T) {
	up := false
	var issuer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up {
			http.Error(w, "starting", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 issuer,
			"authorization_endpoint": issuer + "/authorize",
			"token_endpoint":         issuer + "/token",
			"jwks_uri":               issuer + "/jwks",
		})
	}))
	defer server.Close()
	issuer = server.URL
	c := &Client{Issuer: issuer, ClientID: "roomies"}
	if _, err := c.AuthURL(t.Context(), "https://roomies.test/cb", "s", "c", "n", false); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("first attempt err = %v", err)
	}
	up = true
	authURL, err := c.AuthURL(t.Context(), "https://roomies.test/cb", "s", "c", "n", false)
	if err != nil || !strings.HasPrefix(authURL, issuer+"/authorize?") {
		t.Fatalf("retry = %q, %v", authURL, err)
	}
	if c.LogoutURL(t.Context(), "hint", "https://roomies.test/") != "" {
		t.Fatal("logout url without end_session_endpoint")
	}
}

// discoveryServer serves a discovery document advertising issuerOf(server
// URL) as the issuer, with endpoints under endpointBase(issuer without "/").
func discoveryServer(t *testing.T, tls bool, issuerOf func(serverURL string) string, endpointBase func(self string) string) (*httptest.Server, string) {
	t.Helper()
	var issuer string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := endpointBase(strings.TrimSuffix(issuer, "/"))
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 issuer,
			"authorization_endpoint": base + "/authorize",
			"token_endpoint":         base + "/token",
			"jwks_uri":               base + "/jwks",
			"userinfo_endpoint":      base + "/userinfo",
		})
	})
	server := httptest.NewServer(handler)
	if tls {
		server.Close()
		server = httptest.NewTLSServer(handler)
		trust := httpClient
		httpClient = &http.Client{Timeout: 5 * time.Second, Transport: server.Client().Transport, CheckRedirect: checkRedirect}
		t.Cleanup(func() { httpClient = trust })
	}
	t.Cleanup(server.Close)
	issuer = issuerOf(server.URL)
	return server, issuer
}

func TestIssuerWithTrailingSlashMatchesDiscovery(t *testing.T) {
	_, issuer := discoveryServer(t, false, func(u string) string { return u + "/" }, func(self string) string { return self })
	c := &Client{Issuer: issuer, ClientID: "roomies"}
	if _, err := c.AuthURL(t.Context(), "https://roomies.test/cb", "s", "c", "n", false); err != nil {
		t.Fatalf("issuer %q: %v", issuer, err)
	}
}

func TestHTTPSIssuerRequiresHTTPSEndpoints(t *testing.T) {
	_, issuer := discoveryServer(t, true, sameURL, func(self string) string { return strings.Replace(self, "https://", "http://", 1) })
	c := &Client{Issuer: issuer, ClientID: "roomies"}
	_, err := c.AuthURL(t.Context(), "https://roomies.test/cb", "s", "c", "n", false)
	if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "is not https") {
		t.Fatalf("plain-http endpoints accepted: %v", err)
	}
}

func TestHTTPSDiscoveryRefusesRedirectToHTTP(t *testing.T) {
	plain := httptest.NewServer(http.NotFoundHandler())
	defer plain.Close()
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+r.URL.Path, http.StatusFound)
	}))
	defer secure.Close()
	trust := httpClient
	httpClient = &http.Client{Timeout: 5 * time.Second, Transport: secure.Client().Transport, CheckRedirect: checkRedirect}
	defer func() { httpClient = trust }()
	c := &Client{Issuer: secure.URL, ClientID: "roomies"}
	_, err := c.AuthURL(t.Context(), "https://roomies.test/cb", "s", "c", "n", false)
	if err == nil || !strings.Contains(err.Error(), "refusing redirect from https to http") {
		t.Fatalf("downgrade redirect followed: %v", err)
	}
}

func TestForceLoginAddsPrompt(t *testing.T) {
	_, issuer := discoveryServer(t, false, sameURL, func(self string) string { return self })
	c := &Client{Issuer: issuer, ClientID: "roomies"}
	authURL, err := c.AuthURL(t.Context(), "https://roomies.test/cb", "s", "c", "n", true)
	if err != nil || !strings.Contains(authURL, "prompt=login") {
		t.Fatalf("authURL = %q, %v", authURL, err)
	}
}

func TestMixedCaseHTTPSIssuerStillRequiresHTTPSEndpoints(t *testing.T) {
	for name, tc := range map[string]struct {
		endpoints func(self string) string
		ok        bool
	}{
		"https endpoints": {func(self string) string { return self }, true},
		"http endpoints":  {func(self string) string { return "http://" + strings.SplitN(self, "://", 2)[1] }, false},
	} {
		t.Run(name, func(t *testing.T) {
			_, issuer := discoveryServer(t, true, func(u string) string { return "HTTPS://" + strings.TrimPrefix(u, "https://") }, tc.endpoints)
			c := &Client{Issuer: issuer, ClientID: "roomies"}
			_, err := c.AuthURL(t.Context(), "https://roomies.test/cb", "s", "c", "n", false)
			if (err == nil) != tc.ok {
				t.Fatalf("issuer %q: err = %v", issuer, err)
			}
		})
	}
}

func sameURL(u string) string { return u }
