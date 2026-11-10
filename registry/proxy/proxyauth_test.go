package proxy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/docker/distribution/registry/client/auth"
	"github.com/docker/distribution/registry/client/auth/challenge"
	"github.com/docker/distribution/registry/client/transport"
)

func TestConfigureAuthAllowsSameAuthorityRealm(t *testing.T) {
	t.Parallel()

	var serverURL string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/" {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s/token",service="test-service"`, serverURL))
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(upstream.Close)
	serverURL = upstream.URL

	tokenCreds, err := configureAuth("user", "pass", upstream.URL)
	if err != nil {
		t.Fatalf("configureAuth: %v", err)
	}

	realmURL, err := url.Parse(serverURL + "/token")
	if err != nil {
		t.Fatalf("parse realm: %v", err)
	}

	username, password := tokenCreds.Basic(realmURL)
	if username != "user" || password != "pass" {
		t.Fatalf("unexpected credentials for trusted realm: got (%q, %q)", username, password)
	}
}

func TestConfigureAuthRejectsLoopbackRealmOnDifferentAuthority(t *testing.T) {
	t.Parallel()

	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	t.Cleanup(evil.Close)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/" {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s/token",service="test-service"`, evil.URL))
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(upstream.Close)

	tokenCreds, err := configureAuth("user", "pass", upstream.URL)
	if err != nil {
		t.Fatalf("configureAuth: %v", err)
	}

	realmURL, err := url.Parse(evil.URL + "/token")
	if err != nil {
		t.Fatalf("parse realm: %v", err)
	}

	username, password := tokenCreds.Basic(realmURL)
	if username != "" || password != "" {
		t.Fatalf("unexpected credentials for off-origin realm: got (%q, %q)", username, password)
	}
}

func TestRealmAllowedForDockerHubStyleAuthService(t *testing.T) {
	t.Parallel()

	remoteURL, err := url.Parse("https://registry-1.docker.io")
	if err != nil {
		t.Fatalf("parse remote url: %v", err)
	}

	if !realmAllowed(remoteURL, "https://auth.docker.io/token") {
		t.Fatal("expected docker hub auth realm to remain allowed")
	}
}

func TestRealmAllowedRejectsOffOriginRealms(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		remote string
		realm  string
		want   bool
	}{
		// Off-origin realms on an unrelated registrable domain.
		{remote: "https://registry.example.com", realm: "https://evil.example.net/token", want: false},
		{remote: "https://registry.example.com", realm: "https://registry.example.com.evil.net/token", want: false},
		{remote: "https://registry.example.com", realm: "/token", want: false},
		// Hosts without a registrable domain are only trusted on an exact
		// authority match.
		{remote: "http://registry:5000", realm: "http://evil:5000/token", want: false},
		{remote: "http://registry:5000", realm: "http://registry:5000/token", want: true},
		{remote: "https://registry.example.com.", realm: "https://evil.com./token", want: false},
		// Loopback and IP literals must match the remote authority exactly.
		{remote: "http://localhost:5000", realm: "http://localhost:5001/token", want: false},
		{remote: "http://127.0.0.1:5000", realm: "http://127.0.0.1:5000/token", want: true},
		{remote: "http://127.0.0.1:5000", realm: "http://127.0.0.2:5000/token", want: false},
		// Same registrable domain stays allowed.
		{remote: "https://registry.example.com", realm: "https://auth.example.com/token", want: true},
	} {
		remoteURL, err := url.Parse(tc.remote)
		if err != nil {
			t.Fatalf("parse remote url %q: %v", tc.remote, err)
		}

		if got := realmAllowed(remoteURL, tc.realm); got != tc.want {
			t.Errorf("realmAllowed(%q, %q) = %t, want %t", tc.remote, tc.realm, got, tc.want)
		}
	}
}

func TestRealmFilteringChallengeManagerDropsOffOriginBearer(t *testing.T) {
	t.Parallel()

	remoteURL, err := url.Parse("https://registry.example.com")
	if err != nil {
		t.Fatalf("parse remote url: %v", err)
	}

	endpoint, err := url.Parse("https://registry.example.com/v2/")
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}

	resp := &http.Response{
		StatusCode: http.StatusUnauthorized,
		Header:     make(http.Header),
		Request:    &http.Request{URL: endpoint},
	}
	resp.Header.Add("Www-Authenticate", `Bearer realm="https://auth.example.com/token",service="registry.example.com"`)
	resp.Header.Add("Www-Authenticate", `Bearer realm="https://evil.example.net/token",service="registry.example.com"`)

	manager := challenge.NewFilteringManager(challenge.NewSimpleManager(), func(c challenge.Challenge) bool {
		return !strings.EqualFold(c.Scheme, "bearer") || realmAllowed(remoteURL, c.Parameters["realm"])
	})
	if err := manager.AddResponse(resp); err != nil {
		t.Fatalf("add response: %v", err)
	}

	challenges, err := manager.GetChallenges(*endpoint)
	if err != nil {
		t.Fatalf("get challenges: %v", err)
	}

	if len(challenges) != 1 {
		t.Fatalf("unexpected challenge count: got %d want 1", len(challenges))
	}
	if challenges[0].Scheme != "bearer" {
		t.Fatalf("unexpected surviving challenge: %+v", challenges[0])
	}
	if challenges[0].Parameters["realm"] != "https://auth.example.com/token" {
		t.Fatalf("unexpected surviving realm: %q", challenges[0].Parameters["realm"])
	}
}

func TestRemoteAuthChallengerSkipsOffOriginTokenRealm(t *testing.T) {
	t.Parallel()

	var evilRequests, evilBasicAuth int32
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&evilRequests, 1)
		if _, _, ok := r.BasicAuth(); ok {
			atomic.AddInt32(&evilBasicAuth, 1)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"token":"stolen"}`)
	}))
	t.Cleanup(evil.Close)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/" {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s/token",service="test-service"`, evil.URL))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	remoteURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse remote url: %v", err)
	}

	// Credentials are present for the attacker realm so that, without realm
	// filtering, the token handler would send them via Basic auth.
	c := &remoteAuthChallenger{
		remoteURL: *remoteURL,
		cm:        challenge.NewSimpleManager(),
		cs: credentials{creds: map[string]userpass{
			evil.URL + "/token": {username: "user", password: "pass"},
		}},
	}

	if err := c.tryEstablishChallenges(context.Background()); err != nil {
		t.Fatalf("tryEstablishChallenges: %v", err)
	}

	tr := transport.NewTransport(http.DefaultTransport,
		auth.NewAuthorizer(c.challengeManager(),
			auth.NewTokenHandlerWithOptions(auth.TokenHandlerOptions{
				Transport:   http.DefaultTransport,
				Credentials: c.credentialStore(),
				Scopes: []auth.Scope{
					auth.RepositoryScope{
						Repository: "foo/bar",
						Actions:    []string{"pull"},
					},
				},
			})))

	resp, err := (&http.Client{Transport: tr}).Get(upstream.URL + "/v2/foo/bar/manifests/latest")
	if err != nil {
		t.Fatalf("get manifest: %v", err)
	}
	resp.Body.Close()

	if n := atomic.LoadInt32(&evilRequests); n != 0 {
		t.Fatalf("token request sent to off-origin realm %d time(s) (%d with basic auth)", n, atomic.LoadInt32(&evilBasicAuth))
	}
}
