package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestIdentityRequiresExplicitBoundedAuthority(t *testing.T) {
	for _, change := range []struct {
		name string
		edit func(map[string]any)
	}{
		{"missing policies", func(v map[string]any) { delete(v, "expected_policies") }},
		{"missing ttl", func(v map[string]any) { delete(v, "max_ttl_seconds") }},
		{"zero ttl", func(v map[string]any) { v["max_ttl_seconds"] = 0 }},
		{"excessive ttl", func(v map[string]any) { v["max_ttl_seconds"] = 901 }},
		{"fractional ttl", func(v map[string]any) { v["max_ttl_seconds"] = 1.5 }},
		{"empty role", func(v map[string]any) { v["role"] = "" }},
		{"role path", func(v map[string]any) { v["role"] = "reader/../human" }},
		{"role control", func(v map[string]any) { v["role"] = "reader\n" }},
		{"long role", func(v map[string]any) { v["role"] = strings.Repeat("a", 129) }},
		{"empty policies", func(v map[string]any) { v["expected_policies"] = []any{} }},
		{"missing revoke policy", func(v map[string]any) { v["expected_policies"] = []any{"fixture-reader"} }},
		{"duplicate policy", func(v map[string]any) {
			v["expected_policies"] = []any{"self-revoke", "self-revoke"}
		}},
		{"root policy", func(v map[string]any) { v["expected_policies"] = []any{"root", "self-revoke"} }},
		{"default policy", func(v map[string]any) { v["expected_policies"] = []any{"default", "self-revoke"} }},
		{"policy path", func(v map[string]any) { v["expected_policies"] = []any{"reader/*", "self-revoke"} }},
		{"nonstring policy", func(v map[string]any) { v["expected_policies"] = []any{42, "self-revoke"} }},
		{"too many policies", func(v map[string]any) {
			policies := []any{"self-revoke"}
			for i := range 16 {
				policies = append(policies, fmt.Sprintf("fixture-reader-%d", i))
			}
			v["expected_policies"] = policies
		}},
		{"mount traversal", func(v map[string]any) { v["auth_path"] = "../workstation" }},
		{"unknown setting", func(v map[string]any) { v["token"] = "synthetic-forbidden" }},
	} {
		t.Run(change.name, func(t *testing.T) {
			value := identitySpec(t).AsMap()
			change.edit(value)
			if _, err := parseIdentity(spec(t, value)); err == nil {
				t.Fatal("invalid authority was accepted")
			}
		})
	}
}

func TestIdentityScopedReaderValidatesReturnedAuthority(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(map[string]any)
		ok   bool
	}{
		{"configured reader", func(map[string]any) {}, true},
		{"short lease", func(v map[string]any) { v["lease_duration"] = 1 }, true},
		{"over configured ttl", func(v map[string]any) { v["lease_duration"] = 121 }, false},
		{"wrong policy", func(v map[string]any) {
			v["policies"] = []string{"other-reader", "self-revoke"}
		}, false},
		{"missing reader policy", func(v map[string]any) { v["policies"] = []string{"self-revoke"} }, false},
		{"different token policies", func(v map[string]any) { v["token_policies"] = []string{"other-reader", "self-revoke"} }, false},
		{"duplicate returned policy", func(v map[string]any) {
			v["policies"] = []string{"fixture-reader", "self-revoke", "self-revoke"}
		}, false},
		{"inherited authority", func(v map[string]any) { v["identity_policies"] = []string{"fixture-reader"} }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := identityRequest(t)
			settings := request.Identity.Spec.AsMap()
			settings["role"], settings["max_ttl_seconds"] = "fixture-reader", 120
			settings["expected_policies"] = []any{"self-revoke", "fixture-reader"}
			request.Identity.Spec = spec(t, settings)
			response := authResponse()
			response["policies"], response["token_policies"] = []string{"fixture-reader", "self-revoke"}, []string{"self-revoke", "fixture-reader"}
			response["lease_duration"] = 120
			test.edit(response)
			logins, revokes := 0, 0
			i := identity{store: &memoryStore{values: map[string][]byte{}}, run: runner(frame()), client: &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
				switch r.URL.Path {
				case "/v1/auth/workstation/login":
					logins++
					var payload map[string]string
					if json.NewDecoder(r.Body).Decode(&payload) != nil || len(payload) != 2 || payload["role"] != "fixture-reader" || payload["jwt"] != "synthetic-id" {
						t.Fatal("configured role changed or policy assertions were sent as grants")
					}
					return httpReply(200, map[string]any{"auth": response}), nil
				case "/v1/auth/token/revoke-self":
					revokes++
					return httpReply(204, nil), nil
				default:
					t.Fatal("unexpected authority path")
					return nil, unavailable()
				}
			})}}
			out := &stream{ctx: context.Background()}
			err := i.Authenticate(request, out)
			if test.ok {
				if err != nil || len(out.events) != 1 || revokes != 0 {
					t.Fatal("configured scoped reader was rejected")
				}
				if _, err := i.Logout(context.Background(), request.Identity); err != nil {
					t.Fatal("scoped reader logout failed")
				}
			} else if err == nil || len(out.events) != 0 {
				t.Fatal("unexpected authority reached the consumer")
			}
			if logins != 1 || revokes != 1 {
				t.Fatal("issued reader was not revoked exactly once")
			}
		})
	}
}
