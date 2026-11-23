package handlers_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/roomies/backend/internal/handlers"
	"github.com/roomies/backend/internal/models"
	"github.com/roomies/backend/internal/oidcauth"
)

const oidcTestBase = "https://roomies.test"

// fakeSeq keeps subjects and emails unique when tests share one database.
var fakeSeq atomic.Int64

// fakeOIDC is a minimal provider: discovery, JWKS, token, userinfo. Like
// Better Auth by default, it leaves email and name out of the ID token.
type fakeOIDC struct {
	*httptest.Server
	t                 *testing.T
	key               ed25519.PrivateKey
	pub               ed25519.PublicKey
	nonce, challenge  string
	subject, email    string
	verified          bool
	profileInIDToken  bool
	tokenNonce        string
	userinfoSubject   string
	userinfoCalls     int
	lastRedirectParam string
}

func newFakeOIDC(t *testing.T) *fakeOIDC {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	n := fakeSeq.Add(1)
	f := &fakeOIDC{t: t, key: key, pub: pub, subject: fmt.Sprintf("subject-%d", n), email: fmt.Sprintf("Person-%d@Example.test", n), verified: true}
	mux := http.NewServeMux()
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                f.URL,
			"authorization_endpoint":                f.URL + "/authorize",
			"token_endpoint":                        f.URL + "/token",
			"userinfo_endpoint":                     f.URL + "/userinfo",
			"jwks_uri":                              f.URL + "/jwks",
			"end_session_endpoint":                  f.URL + "/endsession",
			"id_token_signing_alg_values_supported": []string{"EdDSA"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: f.pub, KeyID: "k1", Algorithm: "EdDSA", Use: "sig"}}})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		f.userinfoCalls++
		sub := f.subject
		if f.userinfoSubject != "" {
			sub = f.userinfoSubject
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"sub": sub, "email": f.email, "email_verified": f.verified, "name": "Info Name"})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		id, secret, ok := r.BasicAuth()
		if !ok || id != "roomies" || secret != "secret" {
			http.Error(w, "bad client auth", http.StatusUnauthorized)
			return
		}
		_ = r.ParseForm()
		f.lastRedirectParam = r.Form.Get("redirect_uri")
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != f.challenge {
			http.Error(w, "bad pkce", http.StatusBadRequest)
			return
		}
		nonce := f.nonce
		if f.tokenNonce != "" {
			nonce = f.tokenNonce
		}
		claims := map[string]any{"iss": f.URL, "sub": f.subject, "aud": "roomies", "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(), "nonce": nonce}
		if f.profileInIDToken {
			claims["email"], claims["email_verified"], claims["name"] = f.email, f.verified, "Token Name"
		}
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: jose.JSONWebKey{Key: f.key, KeyID: "k1"}}, nil)
		if err != nil {
			t.Error(err)
			return
		}
		raw, err := josejwt.Signed(signer).Claims(claims).Serialize()
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"at","token_type":"Bearer","id_token":%q}`, raw)
	})
	return f
}

// wantEmail is the normalized email Roomies stores for the fake's user.
func (f *fakeOIDC) wantEmail() string { return strings.ToLower(f.email) }

func (f *fakeOIDC) handler(env *testEnv) *handlers.AuthHandler {
	h := handlers.NewAuthHandler(env.UserRepo, env.JWTSecret, &oidcauth.Client{Issuer: f.URL, ClientID: "roomies", ClientSecret: "secret", Name: "Test ID"})
	h.SetPublicBaseURL(oidcTestBase)
	return h
}

// capture records the nonce and PKCE challenge the provider would see.
func (f *fakeOIDC) capture(authorizationURL string) url.Values {
	f.t.Helper()
	parsed, err := url.Parse(authorizationURL)
	if err != nil || !strings.HasPrefix(authorizationURL, f.URL+"/authorize?") {
		f.t.Fatalf("authorization url = %q", authorizationURL)
	}
	q := parsed.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("state") == "" || q.Get("nonce") == "" {
		f.t.Fatalf("authorization url lacks PKCE/state/nonce: %s", authorizationURL)
	}
	f.nonce, f.challenge = q.Get("nonce"), q.Get("code_challenge")
	return q
}

func webAuthorize(t *testing.T, f *fakeOIDC, h *handlers.AuthHandler) ([]*http.Cookie, url.Values) {
	t.Helper()
	w := httptest.NewRecorder()
	h.OIDCAuthorize(w, httptest.NewRequest(http.MethodGet, oidcTestBase+"/api/auth/oidc/authorize", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("authorize status = %d body = %s", w.Code, w.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return w.Result().Cookies(), f.capture(body["url"])
}

func webCallback(h *handlers.AuthHandler, cookies []*http.Cookie, query string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, oidcTestBase+"/api/auth/oidc/callback?"+query, nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	h.OIDCCallback(w, req)
	return w
}

func signInWeb(t *testing.T, f *fakeOIDC, h *handlers.AuthHandler) *httptest.ResponseRecorder {
	t.Helper()
	cookies, q := webAuthorize(t, f, h)
	return webCallback(h, cookies, "code=provider-code&state="+url.QueryEscape(q.Get("state")))
}

func responseCookie(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == name && cookie.MaxAge >= 0 {
			return cookie
		}
	}
	return nil
}

func TestOIDCAuthorizeSetsTransactionCookies(t *testing.T) {
	env := newTestEnv(t)
	defer env.Cleanup()
	f := newFakeOIDC(t)
	cookies, q := webAuthorize(t, f, f.handler(env))
	if q.Get("redirect_uri") != oidcTestBase+"/api/auth/oidc/callback" || q.Get("scope") != "openid profile email" || q.Get("client_id") != "roomies" {
		t.Fatalf("authorization query = %v", q)
	}
	seen := map[string]bool{}
	for _, cookie := range cookies {
		if !cookie.HttpOnly || !cookie.Secure || cookie.Path != "/" || cookie.Domain != "" || cookie.MaxAge <= 0 || cookie.Value == "" {
			t.Fatalf("transaction cookie = %#v", cookie)
		}
		seen[cookie.Name] = true
	}
	if q.Get("prompt") != "" {
		t.Fatalf("web sign-in must not force prompt: %v", q)
	}
	for _, name := range []string{"__Host-roomies_oauth_state", "__Host-roomies_oauth_verifier", "__Host-roomies_oauth_nonce"} {
		if !seen[name] {
			t.Fatalf("missing cookie %s in %v", name, seen)
		}
	}
}

func TestOIDCCallbackSignsInWebUser(t *testing.T) {
	for _, profileInIDToken := range []bool{false, true} {
		t.Run(fmt.Sprintf("profileInIDToken=%v", profileInIDToken), func(t *testing.T) {
			env := newTestEnv(t)
			defer env.Cleanup()
			f := newFakeOIDC(t)
			f.profileInIDToken = profileInIDToken
			w := signInWeb(t, f, f.handler(env))
			if w.Code != http.StatusFound || w.Header().Get("Location") != oidcTestBase+"/" {
				t.Fatalf("callback status = %d location = %q body = %s", w.Code, w.Header().Get("Location"), w.Body.String())
			}
			if f.lastRedirectParam != oidcTestBase+"/api/auth/oidc/callback" {
				t.Fatalf("token redirect_uri = %q", f.lastRedirectParam)
			}
			wantCalls, wantName := 1, "Info Name"
			if profileInIDToken {
				wantCalls, wantName = 0, "Token Name"
			}
			if f.userinfoCalls != wantCalls {
				t.Fatalf("userinfo calls = %d, want %d", f.userinfoCalls, wantCalls)
			}
			session := responseCookie(w, "__Host-roomies_session")
			if session == nil || !session.HttpOnly || !session.Secure || responseCookie(w, "roomies_session_hint") == nil {
				t.Fatalf("session cookies = %#v", w.Result().Cookies())
			}
			me := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
			me.AddCookie(session)
			meRes := httptest.NewRecorder()
			env.Router.ServeHTTP(meRes, me)
			var user models.User
			if err := json.Unmarshal(meRes.Body.Bytes(), &user); err != nil || meRes.Code != http.StatusOK {
				t.Fatalf("me status = %d body = %s", meRes.Code, meRes.Body.String())
			}
			if user.Email != f.wantEmail() || user.Name != wantName || strings.Contains(meRes.Body.String(), f.subject) || strings.Contains(meRes.Body.String(), f.URL) {
				t.Fatalf("me = %s", meRes.Body.String())
			}
		})
	}
}

func TestOIDCCallbackFailuresRedirectWithCode(t *testing.T) {
	cases := map[string]struct {
		setup func(*fakeOIDC)
		query func(state string) string
		want  string
	}{
		"bad state":        {query: func(string) string { return "code=c&state=forged" }, want: "failed"},
		"nonce mismatch":   {setup: func(f *fakeOIDC) { f.tokenNonce = "other-nonce" }, want: "failed"},
		"sub mismatch":     {setup: func(f *fakeOIDC) { f.userinfoSubject = "someone-else" }, want: "failed"},
		"unverified email": {setup: func(f *fakeOIDC) { f.verified = false }, want: "email_unverified"},
		"provider error":   {query: func(state string) string { return "error=access_denied&error_description=nope&state=" + state }, want: "provider"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			env := newTestEnv(t)
			defer env.Cleanup()
			f := newFakeOIDC(t)
			if tc.setup != nil {
				tc.setup(f)
			}
			h := f.handler(env)
			cookies, q := webAuthorize(t, f, h)
			query := "code=provider-code&state=" + url.QueryEscape(q.Get("state"))
			if tc.query != nil {
				query = tc.query(url.QueryEscape(q.Get("state")))
			}
			w := webCallback(h, cookies, query)
			if w.Code != http.StatusFound || w.Header().Get("Location") != oidcTestBase+"/?auth_error="+tc.want {
				t.Fatalf("status = %d location = %q", w.Code, w.Header().Get("Location"))
			}
			if responseCookie(w, "__Host-roomies_session") != nil {
				t.Fatal("failed sign-in set a session cookie")
			}
			if _, err := env.UserRepo.GetByAuthIdentity(t.Context(), f.URL, f.subject); err == nil {
				t.Fatal("failed sign-in created a user")
			}
		})
	}
}

func TestOIDCCallbackRefusesEmailOfAnotherSubject(t *testing.T) {
	env := newTestEnv(t)
	defer env.Cleanup()
	f := newFakeOIDC(t)
	if _, err := env.UserRepo.UpsertFromOIDC(t.Context(), f.URL, "other-subject", f.wantEmail(), "Other"); err != nil {
		t.Fatal(err)
	}
	w := signInWeb(t, f, f.handler(env))
	if w.Header().Get("Location") != oidcTestBase+"/?auth_error=email_in_use" {
		t.Fatalf("location = %q", w.Header().Get("Location"))
	}
}

func TestOIDCNativeSignInAndExchange(t *testing.T) {
	env := newTestEnv(t)
	defer env.Cleanup()
	f := newFakeOIDC(t)
	h := f.handler(env)
	appCode := func(verifier string) string {
		t.Helper()
		sum := sha256.Sum256([]byte(verifier))
		start := httptest.NewRecorder()
		h.OIDCNativeStart(start, httptest.NewRequest(http.MethodGet, oidcTestBase+"/api/auth/oidc/native?app_challenge="+base64.RawURLEncoding.EncodeToString(sum[:]), nil))
		if start.Code != http.StatusFound {
			t.Fatalf("native start status = %d body = %s", start.Code, start.Body.String())
		}
		q := f.capture(start.Header().Get("Location"))
		if q.Get("redirect_uri") != oidcTestBase+"/api/auth/oidc/native/callback" || q.Get("prompt") != "login" {
			t.Fatalf("native authorization query = %v", q)
		}
		req := httptest.NewRequest(http.MethodGet, oidcTestBase+"/api/auth/oidc/native/callback?code=provider-code&state="+url.QueryEscape(q.Get("state")), nil)
		for _, cookie := range start.Result().Cookies() {
			req.AddCookie(cookie)
		}
		callback := httptest.NewRecorder()
		h.OIDCNativeCallback(callback, req)
		location := callback.Header().Get("Location")
		if callback.Code != http.StatusFound || !strings.HasPrefix(location, "app.roomies.roomies://oidc?code=") {
			t.Fatalf("native callback status = %d location = %q", callback.Code, location)
		}
		parsed, _ := url.Parse(location)
		return parsed.Query().Get("code")
	}
	exchange := func(code, verifier string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"code": code, "code_verifier": verifier})
		w := httptest.NewRecorder()
		h.OIDCExchange(w, httptest.NewRequest(http.MethodPost, "/api/auth/oidc/exchange", bytes.NewReader(body)))
		return w
	}

	if w := exchange(appCode("app-verifier-one"), "wrong-verifier"); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong verifier status = %d body = %s", w.Code, w.Body.String())
	}
	code := appCode("app-verifier-two")
	w := exchange(code, "app-verifier-two")
	if w.Code != http.StatusOK {
		t.Fatalf("exchange status = %d body = %s", w.Code, w.Body.String())
	}
	var auth models.AuthResponse
	if err := json.Unmarshal(w.Body.Bytes(), &auth); err != nil || auth.Token == "" || auth.User.Email != f.wantEmail() {
		t.Fatalf("exchange body = %s", w.Body.String())
	}
	assertNoIDTokenInSession(t, auth.Token)
	if w := exchange(code, "app-verifier-two"); w.Code != http.StatusUnauthorized {
		t.Fatalf("reused app code status = %d", w.Code)
	}

	bad := httptest.NewRecorder()
	h.OIDCNativeStart(bad, httptest.NewRequest(http.MethodGet, "/api/auth/oidc/native?app_challenge=short", nil))
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("bad challenge status = %d", bad.Code)
	}
}

func TestOIDCNativeCallbackFailureRedirectsToApp(t *testing.T) {
	env := newTestEnv(t)
	defer env.Cleanup()
	f := newFakeOIDC(t)
	w := httptest.NewRecorder()
	f.handler(env).OIDCNativeCallback(w, httptest.NewRequest(http.MethodGet, "/api/auth/oidc/native/callback?code=c&state=s", nil))
	if w.Code != http.StatusFound || w.Header().Get("Location") != "app.roomies.roomies://oidc?error=failed" {
		t.Fatalf("status = %d location = %q", w.Code, w.Header().Get("Location"))
	}
}

func TestOIDCExchangeIsRateLimited(t *testing.T) {
	env := newTestEnv(t)
	defer env.Cleanup()
	h := newFakeOIDC(t).handler(env)
	h.SetRateLimit(2)
	status := 0
	for attempt := 0; attempt < 3; attempt++ {
		w := httptest.NewRecorder()
		h.OIDCExchange(w, httptest.NewRequest(http.MethodPost, "/api/auth/oidc/exchange", strings.NewReader(`{"code":"x","code_verifier":"y"}`)))
		status = w.Code
	}
	if status != http.StatusTooManyRequests {
		t.Fatalf("third exchange status = %d", status)
	}
}

// assertNoIDTokenInSession checks the readable session JWT carries only the
// session claims, never the provider ID token, and returns its jti.
func assertNoIDTokenInSession(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if len(parts) != 3 || err != nil {
		t.Fatalf("session token = %q", token)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	for key := range claims {
		switch key {
		case "user_id", "email", "jti", "exp", "iat":
		default:
			t.Fatalf("session token carries %q: %s", key, payload)
		}
	}
	return claims["jti"].(string)
}

func storedIDTokens(t *testing.T, env *testEnv, jti string) int {
	t.Helper()
	var count int
	if err := env.DB.Get(&count, `SELECT COUNT(*) FROM session_id_tokens WHERE jti = $1`, jti); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestLogoutReturnsProviderLogoutURL(t *testing.T) {
	env := newTestEnv(t)
	defer env.Cleanup()
	f := newFakeOIDC(t)
	h := f.handler(env)
	session := responseCookie(signInWeb(t, f, h), "__Host-roomies_session")
	if session == nil {
		t.Fatal("sign-in did not set a session")
	}
	jti := assertNoIDTokenInSession(t, session.Value)
	if storedIDTokens(t, env, jti) != 1 {
		t.Fatal("logout hint was not stored server-side")
	}
	req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	req.AddCookie(session)
	w := httptest.NewRecorder()
	h.Logout(w, req)
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || w.Code != http.StatusOK {
		t.Fatalf("logout status = %d body = %s", w.Code, w.Body.String())
	}
	logout, err := url.Parse(body["logout_url"])
	if err != nil || !strings.HasPrefix(body["logout_url"], f.URL+"/endsession?") {
		t.Fatalf("logout_url = %q", body["logout_url"])
	}
	q := logout.Query()
	if len(strings.Split(q.Get("id_token_hint"), ".")) != 3 || q.Get("post_logout_redirect_uri") != oidcTestBase+"/" || q.Get("client_id") != "roomies" {
		t.Fatalf("logout query = %v", q)
	}
	if storedIDTokens(t, env, jti) != 0 {
		t.Fatal("logout left the stored hint behind")
	}
	me := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	me.AddCookie(session)
	meRes := httptest.NewRecorder()
	env.Router.ServeHTTP(meRes, me)
	if meRes.Code != http.StatusUnauthorized {
		t.Fatalf("signed-out session still works: %d", meRes.Code)
	}
}

func TestExpiredSessionIDTokensArePurged(t *testing.T) {
	env := newTestEnv(t)
	defer env.Cleanup()
	now := time.Now()
	old, live := models.NewID(), models.NewID()
	if err := env.UserRepo.SaveSessionIDToken(t.Context(), old, "old.id.token", now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := env.UserRepo.SaveSessionIDToken(t.Context(), live, "live.id.token", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := env.UserRepo.PurgeExpiredSessionIDTokens(t.Context(), now); err != nil {
		t.Fatal(err)
	}
	if storedIDTokens(t, env, old) != 0 || storedIDTokens(t, env, live) != 1 {
		t.Fatal("purge removed the wrong logout hints")
	}
}

func TestOIDCSameSubjectFromAnotherIssuerIsAnotherUser(t *testing.T) {
	env := newTestEnv(t)
	defer env.Cleanup()
	first, second := newFakeOIDC(t), newFakeOIDC(t)
	second.subject = first.subject
	for _, f := range []*fakeOIDC{first, second} {
		if w := signInWeb(t, f, f.handler(env)); w.Header().Get("Location") != oidcTestBase+"/" {
			t.Fatalf("sign-in via %s: location = %q", f.URL, w.Header().Get("Location"))
		}
	}
	a, errA := env.UserRepo.GetByAuthIdentity(t.Context(), first.URL, first.subject)
	b, errB := env.UserRepo.GetByAuthIdentity(t.Context(), second.URL, second.subject)
	if errA != nil || errB != nil || a.ID == b.ID || a.Email != first.wantEmail() || b.Email != second.wantEmail() {
		t.Fatalf("users = %#v %#v (%v, %v)", a, b, errA, errB)
	}
}

func TestPlainHTTPDeploymentKeepsPlainCookieNames(t *testing.T) {
	env := newTestEnv(t)
	defer env.Cleanup()
	f := newFakeOIDC(t)
	h := f.handler(env)
	h.SetPublicBaseURL("http://localhost:8080")
	start := httptest.NewRecorder()
	h.OIDCAuthorize(start, httptest.NewRequest(http.MethodGet, "http://localhost:8080/api/auth/oidc/authorize", nil))
	var body map[string]string
	if err := json.Unmarshal(start.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	q := f.capture(body["url"])
	for _, cookie := range start.Result().Cookies() {
		if strings.HasPrefix(cookie.Name, "__Host-") || cookie.Secure {
			t.Fatalf("plain-http transaction cookie = %#v", cookie)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "http://localhost:8080/api/auth/oidc/callback?code=c&state="+url.QueryEscape(q.Get("state")), nil)
	for _, cookie := range start.Result().Cookies() {
		req.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	h.OIDCCallback(w, req)
	if w.Header().Get("Location") != "http://localhost:8080/" || responseCookie(w, "roomies_session") == nil {
		t.Fatalf("location = %q cookies = %v", w.Header().Get("Location"), w.Result().Cookies())
	}
}

func TestHTTPSDeploymentIgnoresUnprefixedSessionCookie(t *testing.T) {
	env := newTestEnv(t)
	defer env.Cleanup()
	token := registerUser(t, env.Router, "Tossed", "tossed@test.com", "unused")
	for name, want := range map[string]int{"roomies_session": http.StatusUnauthorized, "__Host-roomies_session": http.StatusOK} {
		req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
		req.AddCookie(&http.Cookie{Name: name, Value: token})
		w := httptest.NewRecorder()
		env.Router.ServeHTTP(w, req)
		if w.Code != want {
			t.Fatalf("cookie %s: status = %d, want %d", name, w.Code, want)
		}
	}
}

func TestAuthRoutesWithoutOIDC(t *testing.T) {
	env := newTestEnv(t)
	defer env.Cleanup()
	request := func(method, path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		env.Router.ServeHTTP(w, httptest.NewRequest(method, path, strings.NewReader(`{}`)))
		return w
	}
	config := request(http.MethodGet, "/api/auth/config")
	var body map[string]any
	if err := json.Unmarshal(config.Body.Bytes(), &body); err != nil || body["oidc"] != false || len(body) != 2 {
		t.Fatalf("config = %s", config.Body.String())
	}
	for _, path := range []string{"/api/auth/oidc/authorize", "/api/auth/oidc/callback?code=c&state=s", "/api/auth/oidc/native?app_challenge=x"} {
		if w := request(http.MethodGet, path); w.Code != http.StatusServiceUnavailable {
			t.Fatalf("GET %s status = %d", path, w.Code)
		}
	}
	for _, route := range [][2]string{
		{http.MethodPost, "/api/auth/register"},
		{http.MethodPost, "/api/auth/login"},
		{http.MethodGet, "/api/auth/workos/authorize"},
		{http.MethodPost, "/api/auth/workos/callback"},
		{http.MethodPost, "/api/auth/oidc/callback"},
	} {
		if w := request(route[0], route[1]); w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s %s status = %d", route[0], route[1], w.Code)
		}
	}
}
