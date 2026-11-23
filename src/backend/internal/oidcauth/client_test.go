package oidcauth

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
	if _, err := c.AuthURL(t.Context(), "https://roomies.test/cb", "s", "c", "n"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("first attempt err = %v", err)
	}
	up = true
	authURL, err := c.AuthURL(t.Context(), "https://roomies.test/cb", "s", "c", "n")
	if err != nil || !strings.HasPrefix(authURL, issuer+"/authorize?") {
		t.Fatalf("retry = %q, %v", authURL, err)
	}
	if c.LogoutURL(t.Context(), "hint", "https://roomies.test/") != "" {
		t.Fatal("logout url without end_session_endpoint")
	}
}
