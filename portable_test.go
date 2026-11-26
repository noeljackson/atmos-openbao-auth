package main

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestNativeOIDCExchangeDoesNotRequireALocalSessionClient(t *testing.T) {
	request := identityRequest(t)
	config := request.Identity.Spec.AsMap()
	config["address"] = "https://vault.example.org:8200/"
	config["issuer"] = "https://login.example.org/realms/team"
	config["auth_path"] = "team/jwt"
	config["self_revoke_policy"] = "team-self-revoke"
	config["expected_policies"] = []any{"reader", "team-self-revoke"}
	delete(config, "session_client")
	request.Identity.Spec = spec(t, config)
	upstream := request.Upstream.Data.AsMap()
	upstream["issuer"] = config["issuer"]
	request.Upstream.Data = spec(t, upstream)
	logins, revokes := 0, 0
	i := identity{store: &memoryStore{values: map[string][]byte{}}, run: func(context.Context, string, func(sessionFrame) error) error {
		t.Fatal("a provider-neutral exchange contacted the optional session adapter")
		return errors.New("unexpected session client")
	}, client: &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "vault.example.org:8200" {
			t.Fatal("configured OpenBao authority changed")
		}
		switch r.URL.Path {
		case "/v1/auth/team/jwt/login":
			logins++
			auth := authResponse()
			auth["policies"], auth["token_policies"] = []string{"reader", "team-self-revoke"}, []string{"team-self-revoke", "reader"}
			return httpReply(200, map[string]any{"auth": auth}), nil
		case "/v1/auth/token/revoke-self":
			revokes++
			return httpReply(204, nil), nil
		default:
			t.Fatal("configured authentication mount changed")
			return nil, unavailable()
		}
	})}}
	out := &stream{ctx: t.Context()}
	if err := i.Authenticate(request, out); err != nil || len(out.events) != 1 {
		t.Fatal("provider-neutral OIDC exchange failed")
	}
	if _, err := i.Logout(t.Context(), request.Identity); err != nil || logins != 1 || revokes != 1 {
		t.Fatal("provider-neutral lease was not revoked exactly once")
	}
}

func TestConfigRejectsCredentialURLsAndEscapingMounts(t *testing.T) {
	for _, field := range []string{"address", "issuer"} {
		for _, value := range []string{"http://example.org", "https://user:synthetic@example.org", "https://example.org?token=synthetic", "https://example.org#fragment", "https://", "https://example.org:bad", "https://example.org\n"} {
			t.Run(field+"/"+value, func(t *testing.T) {
				config := identitySpec(t).AsMap()
				config[field] = value
				if _, err := parseIdentity(spec(t, config)); err == nil {
					t.Fatal("unsafe service URL accepted")
				}
			})
		}
	}
	for _, value := range []string{"/jwt", "jwt/", "jwt//team", "../jwt", "jwt/../other", "jwt/./other", "jwt%2fother", "jwt\\other", "jwt?role=admin"} {
		config := identitySpec(t).AsMap()
		config["auth_path"] = value
		if _, err := parseIdentity(spec(t, config)); err == nil {
			t.Fatal("escaping authentication mount accepted")
		}
	}
	for _, value := range []string{"session-client", "../session-client", "~/../session-client", "/usr/../session-client", "/session-client\n"} {
		config := identitySpec(t).AsMap()
		config["session_client"] = value
		if _, err := parseIdentity(spec(t, config)); err == nil {
			t.Fatal("ambiguous session-client path accepted")
		}
	}
}

func TestSessionChangesDuringExchangeFenceAndRevoke(t *testing.T) {
	for _, change := range []string{"logout", "refresh", "subject", "expiry"} {
		t.Run(change, func(t *testing.T) {
			checks, logins, revokes := 0, 0, 0
			i := identity{store: &memoryStore{values: map[string][]byte{}}, run: func(ctx context.Context, action string, consume func(sessionFrame) error) error {
				checks++
				value := frame()
				if checks == 2 {
					switch change {
					case "logout":
						return errors.New("synthetic closed session")
					case "refresh":
						value.Credential = "synthetic-refreshed-id"
					case "subject":
						value.Subject = "synthetic-other-owner"
					case "expiry":
						value.ExpiresAt = time.Now().Add(-time.Second).Format(time.RFC3339)
					}
				}
				return runner(value)(ctx, action, consume)
			}, client: &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
				if strings.HasSuffix(r.URL.Path, "revoke-self") {
					revokes++
					return httpReply(204, nil), nil
				}
				logins++
				return httpReply(200, map[string]any{"auth": authResponse()}), nil
			})}}
			out := &stream{ctx: t.Context()}
			if i.Authenticate(identityRequest(t), out) == nil || len(out.events) != 0 || checks != 2 || logins != 1 || revokes != 1 {
				t.Fatal("a changed session received an OpenBao credential or escaped revocation")
			}
		})
	}
}

func TestCancellationDuringIssuanceRetainsCleanupCustody(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	logins, revokes := 0, 0
	i := identity{store: &memoryStore{values: map[string][]byte{}}, run: runner(frame()), client: &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "revoke-self") {
			revokes++
			if r.Context().Err() != nil {
				t.Fatal("canceled caller abandoned revocation")
			}
			return httpReply(204, nil), nil
		}
		logins++
		cancel()
		if r.Context().Err() != nil {
			t.Fatal("cancellation discarded custody of an in-flight issuance response")
		}
		return httpReply(200, map[string]any{"auth": authResponse()}), nil
	})}}
	out := &stream{ctx: ctx}
	if i.Authenticate(identityRequest(t), out) == nil || len(out.events) != 0 || logins != 1 || revokes != 1 {
		t.Fatal("canceled issuance escaped cleanup or dispatched credentials")
	}
}

func TestLogoutCannotSendALeaseToAChangedAddress(t *testing.T) {
	request := identityRequest(t)
	revokes := 0
	i := identity{store: &memoryStore{values: map[string][]byte{}}, run: runner(frame()), client: &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "revoke-self") {
			revokes++
			if r.URL.Host != "openbao.example.invalid" {
				t.Fatal("lease was sent to a substituted server")
			}
			return httpReply(204, nil), nil
		}
		return httpReply(200, map[string]any{"auth": authResponse()}), nil
	})}}
	if err := i.Authenticate(request, &stream{ctx: t.Context()}); err != nil {
		t.Fatal(err)
	}
	config := request.Identity.Spec.AsMap()
	config["address"] = "https://substituted.example.invalid"
	request.Identity.Spec = spec(t, config)
	if _, err := i.Logout(t.Context(), request.Identity); err == nil || revokes != 0 {
		t.Fatal("changed cleanup authority accepted")
	}
	config["address"] = "https://openbao.example.invalid"
	request.Identity.Spec = spec(t, config)
	if _, err := i.Logout(t.Context(), request.Identity); err != nil || revokes != 1 {
		t.Fatal("original cleanup authority was not preserved")
	}
}
