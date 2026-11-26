package main

import (
	"bytes"
	"encoding/json"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"google.golang.org/protobuf/types/known/structpb"
)

type identitySettings struct {
	Address          string   `json:"address"`
	Issuer           string   `json:"issuer"`
	ClientID         string   `json:"client_id"`
	Subject          string   `json:"subject"`
	AuthPath         string   `json:"auth_path"`
	Role             string   `json:"role"`
	ExpectedPolicies []string `json:"expected_policies"`
	SelfRevokePolicy string   `json:"self_revoke_policy"`
	MaxTTLSeconds    int      `json:"max_ttl_seconds"`
	SessionClient    string   `json:"session_client,omitempty"`
}

type providerSettings struct {
	Issuer        string `json:"issuer"`
	ClientID      string `json:"client_id"`
	Subject       string `json:"subject"`
	LoginMethod   string `json:"login_method"`
	SessionClient string `json:"session_client"`
}

var authorityNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)

func validBaoToken(token string) bool {
	return len(token) > 0 && len(token) <= 2048 && tokenPattern.MatchString(token)
}

func decodeSettings(spec *structpb.Struct, target any) error {
	if spec == nil {
		return invalid()
	}
	raw, err := json.Marshal(spec.AsMap())
	if err != nil {
		return invalid()
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return invalid()
	}
	return nil
}

func httpsURL(raw string, originOnly bool) bool {
	if len(raw) > 2048 {
		return false
	}
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil &&
		u.Opaque == "" && u.RawQuery == "" && u.Fragment == "" &&
		(!originOnly || (u.RawPath == "" && (u.Path == "" || u.Path == "/")))
}

func sessionClientPath(raw string) bool {
	path := strings.TrimPrefix(raw, "~/")
	return raw != "" && len(raw) <= 4096 && !strings.ContainsAny(raw, "\x00\r\n") &&
		(filepath.IsAbs(raw) || strings.HasPrefix(raw, "~/")) &&
		filepath.Clean(path) == path && path != "." && path != ".." && !strings.HasPrefix(path, "../")
}

func authMount(raw string) bool {
	if raw == "" || len(raw) > 128 {
		return false
	}
	for _, part := range strings.Split(raw, "/") {
		if part == "." || part == ".." || !authorityNamePattern.MatchString(part) {
			return false
		}
	}
	return true
}

func parseIdentity(spec *structpb.Struct) (identitySettings, error) {
	var value identitySettings
	if decodeSettings(spec, &value) != nil || !httpsURL(value.Address, true) || !httpsURL(value.Issuer, false) ||
		value.ClientID == "" || value.Subject == "" || !authMount(value.AuthPath) ||
		!authorityNamePattern.MatchString(value.Role) || value.MaxTTLSeconds < 1 || value.MaxTTLSeconds > 900 ||
		!validExpectedPolicies(value.ExpectedPolicies, value.SelfRevokePolicy) ||
		(value.SessionClient != "" && !sessionClientPath(value.SessionClient)) {
		return value, invalid()
	}
	value.Address = strings.TrimSuffix(value.Address, "/")
	return value, nil
}

func validExpectedPolicies(policies []string, revokePolicy string) bool {
	if len(policies) < 1 || len(policies) > 16 || !authorityNamePattern.MatchString(revokePolicy) || !slices.Contains(policies, revokePolicy) {
		return false
	}
	seen := make(map[string]bool, len(policies))
	for _, policy := range policies {
		if !authorityNamePattern.MatchString(policy) || policy == "root" || policy == "default" || seen[policy] {
			return false
		}
		seen[policy] = true
	}
	return true
}

func parseProvider(spec *structpb.Struct) (providerSettings, error) {
	var value providerSettings
	if decodeSettings(spec, &value) != nil || !httpsURL(value.Issuer, false) || value.ClientID == "" || value.Subject == "" ||
		!sessionClientPath(value.SessionClient) ||
		(value.LoginMethod != "existing" && value.LoginMethod != "browser" && value.LoginMethod != "device") {
		return value, invalid()
	}
	return value, nil
}
