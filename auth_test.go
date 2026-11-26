package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pluginv1 "github.com/cloudposse/atmos/sdk/proto/atmos/plugin/v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type stream struct {
	ctx    context.Context
	events []*pluginv1.AuthenticateEvent
	err    error
}

func (s *stream) Context() context.Context { return s.ctx }
func (s *stream) Send(value *pluginv1.AuthenticateEvent) error {
	if s.err != nil {
		return s.err
	}
	s.events = append(s.events, value)
	return nil
}
func (*stream) SetHeader(metadata.MD) error  { return nil }
func (*stream) SendHeader(metadata.MD) error { return nil }
func (*stream) SetTrailer(metadata.MD)       {}
func (*stream) SendMsg(any) error            { return nil }
func (*stream) RecvMsg(any) error            { return io.EOF }

func spec(t *testing.T, value map[string]any) *structpb.Struct {
	t.Helper()
	result, err := structpb.NewStruct(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func providerSpec(t *testing.T, method string) *structpb.Struct {
	return spec(t, map[string]any{"issuer": "https://issuer.example.invalid", "client_id": "synthetic-client", "subject": "synthetic-owner", "login_method": method, "session_client": "/synthetic/session-client"})
}
func identitySpec(t *testing.T) *structpb.Struct {
	return spec(t, map[string]any{"address": "https://openbao.example.invalid", "issuer": "https://issuer.example.invalid", "client_id": "synthetic-client", "subject": "synthetic-owner", "auth_path": "workstation", "role": "human", "expected_policies": []any{"fixture-reader", "self-revoke"}, "self_revoke_policy": "self-revoke", "max_ttl_seconds": 900, "session_client": "/synthetic/session-client"})
}
func frame() sessionFrame {
	return sessionFrame{Done: true, Issuer: "https://issuer.example.invalid", ClientID: "synthetic-client", Subject: "synthetic-owner", Credential: "synthetic-id", AccessToken: "synthetic-access", AccessExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339), ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339)}
}
func runner(value sessionFrame) sessionRunner {
	return func(_ context.Context, action string, consume func(sessionFrame) error) error {
		if action != "atmos-oidc" {
			return errors.New("unexpected approval")
		}
		return consume(value)
	}
}

func TestProviderUsesNativeEnvelopeAndNeverApprovesComponentCalls(t *testing.T) {
	for _, method := range []string{"existing", "browser", "device"} {
		p := provider{run: runner(frame())}
		out := &stream{ctx: context.Background()}
		err := p.Authenticate(&pluginv1.ProviderRequest{Spec: providerSpec(t, method), Invocation: &pluginv1.Invocation{Interactive: true, Stack: "example", Component: "fixture"}}, out)
		if err != nil {
			t.Fatal(err)
		}
		if len(out.events) != 1 {
			t.Fatal("unexpected events")
		}
		credentials := out.events[0].GetResult()
		if credentials.GetType() != "oidc/v1" || credentials.GetData().GetFields()["id_token"].GetStringValue() != "synthetic-id" || len(credentials.GetSensitiveKeys()) != 2 || credentials.GetData().GetFields()["access_token"].GetStringValue() != "synthetic-access" {
			t.Fatal("invalid native credential envelope")
		}
	}
}

func TestProviderRejectsWrongSessionMetadataAndExpiredCredentials(t *testing.T) {
	for _, change := range []func(*sessionFrame){
		func(f *sessionFrame) { f.Issuer = "https://other.invalid" }, func(f *sessionFrame) { f.ClientID = "other" },
		func(f *sessionFrame) { f.Subject = "other" }, func(f *sessionFrame) { f.Credential = "" },
		func(f *sessionFrame) { f.ExpiresAt = time.Now().Add(-time.Minute).Format(time.RFC3339) },
		func(f *sessionFrame) { f.ExpiresAt = "bad" }, func(f *sessionFrame) { f.Done = false },
		func(f *sessionFrame) { f.AccessToken = "" },
		func(f *sessionFrame) { f.AccessExpiresAt = "bad" },
		func(f *sessionFrame) { f.AccessExpiresAt = time.Now().Add(-time.Minute).Format(time.RFC3339) },
	} {
		value := frame()
		change(&value)
		p := provider{run: runner(value)}
		out := &stream{ctx: context.Background()}
		if p.Authenticate(&pluginv1.ProviderRequest{Spec: providerSpec(t, "existing")}, out) == nil || len(out.events) != 0 {
			t.Fatal("invalid credential escaped")
		}
	}
}

func TestProviderExplicitDeviceLoginUsesNativeInteraction(t *testing.T) {
	p := provider{run: func(_ context.Context, action string, consume func(sessionFrame) error) error {
		if action != "atmos-login-device" {
			t.Fatal("wrong login mode")
		}
		if err := consume(sessionFrame{Prompt: &sessionPrompt{Device: true, URL: "https://issuer.example.invalid/device", Code: "synthetic-code"}}); err != nil {
			return err
		}
		return consume(frame())
	}}
	out := &stream{ctx: context.Background()}
	if err := p.Authenticate(&pluginv1.ProviderRequest{Spec: providerSpec(t, "device"), Invocation: &pluginv1.Invocation{Interactive: true}}, out); err != nil {
		t.Fatal(err)
	}
	if len(out.events) != 2 || out.events[0].GetInteraction().GetKind() != "device_code" || out.events[1].GetResult() == nil {
		t.Fatal("native interaction/result order")
	}
}

func TestExplicitBrowserLoginUsesOnlyNativeBrowserAPI(t *testing.T) {
	opened := false
	p := provider{open: func(_ context.Context, url string) error {
		opened = true
		if url != "https://issuer.example.invalid/oauth/v2/authorize?synthetic=1" {
			t.Fatal("wrong browser authority")
		}
		return nil
	},
		run: func(_ context.Context, action string, consume func(sessionFrame) error) error {
			if action != "atmos-login" {
				t.Fatal("wrong login action")
			}
			if err := consume(sessionFrame{Prompt: &sessionPrompt{URL: "https://issuer.example.invalid/oauth/v2/authorize?synthetic=1"}}); err != nil {
				return err
			}
			return consume(frame())
		}}
	out := &stream{ctx: context.Background()}
	if err := p.Authenticate(&pluginv1.ProviderRequest{Spec: providerSpec(t, "browser"), Invocation: &pluginv1.Invocation{Interactive: true}}, out); err != nil {
		t.Fatal(err)
	}
	if !opened || len(out.events) != 1 || out.events[0].GetResult() == nil {
		t.Fatal("browser login was not natively presented")
	}
}

func TestNativeClientExecutableRejectsSymlinksAndWritableOrMissingFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access")
	if validateSessionExecutable(path) == nil {
		t.Fatal("missing executable accepted")
	}
	if err := os.WriteFile(path, []byte("synthetic binary"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := validateSessionExecutable(path); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0600, 0720, 0702} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if validateSessionExecutable(path) == nil {
			t.Fatal("unsafe executable accepted")
		}
	}
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "linked-access")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if validateSessionExecutable(link) == nil {
		t.Fatal("symlink accepted")
	}
}

type memoryStore struct {
	values  map[string][]byte
	failPut bool
}

func (s *memoryStore) Get(_ context.Context, key string) ([]byte, bool, error) {
	v, ok := s.values[key]
	return v, ok, nil
}
func (s *memoryStore) Put(_ context.Context, key string, v []byte) error {
	if s.failPut {
		return errors.New("synthetic private storage failure")
	}
	s.values[key] = append([]byte(nil), v...)
	return nil
}
func (s *memoryStore) Delete(_ context.Context, key string) error { delete(s.values, key); return nil }

type transport func(*http.Request) (*http.Response, error)

func (f transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func identityRequest(t *testing.T) *pluginv1.IdentityAuthenticateRequest {
	f := frame()
	return &pluginv1.IdentityAuthenticateRequest{Identity: &pluginv1.IdentityRequest{Spec: identitySpec(t)}, Upstream: &pluginv1.Credentials{
		Type: "oidc/v1", ExpiresAt: timestamppb.New(time.Now().Add(time.Minute)),
		Data: spec(t, map[string]any{"issuer": f.Issuer, "client_id": f.ClientID, "subject": f.Subject, "id_token": f.Credential, "id_token_expires_at": f.ExpiresAt}),
	}}
}
func authResponse() map[string]any {
	policies := []string{"fixture-reader", "self-revoke"}
	return map[string]any{"client_token": "synthetic-bao", "policies": policies, "token_policies": policies, "identity_policies": []string{}, "lease_duration": 900}
}
func httpReply(code int, value any) *http.Response {
	raw, _ := json.Marshal(value)
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(string(raw))), Header: make(http.Header)}
}

func TestIdentityExchangeAndLogoutHaveExactAuthorityAndNoAmbientFallback(t *testing.T) {
	t.Setenv("VAULT_TOKEN", "synthetic-ambient")
	t.Setenv("BAO_TOKEN", "synthetic-ambient")
	requests := []string{}
	i := identity{store: &memoryStore{values: map[string][]byte{}}, run: runner(frame()), client: &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		requests = append(requests, r.URL.Path)
		if r.URL.Host != "openbao.example.invalid" {
			t.Fatal("authority changed")
		}
		if strings.HasSuffix(r.URL.Path, "/login") {
			var payload map[string]string
			json.NewDecoder(r.Body).Decode(&payload)
			if payload["role"] != "human" || payload["jwt"] != "synthetic-id" || r.Header.Get("X-Vault-Token") != "" {
				t.Fatal("expanded or ambient authority")
			}
			return httpReply(200, map[string]any{"auth": authResponse()}), nil
		}
		if r.Header.Get("X-Vault-Token") != "synthetic-bao" {
			t.Fatal("incorrect revoke capability")
		}
		return httpReply(204, nil), nil
	})}}
	out := &stream{ctx: context.Background()}
	request := identityRequest(t)
	if err := i.Authenticate(request, out); err != nil {
		t.Fatal(err)
	}
	credential := out.events[0].GetResult()
	if credential.GetType() != "environment/v1" || len(credential.GetData().GetFields()) != 1 || credential.GetData().GetFields()["VAULT_TOKEN"].GetStringValue() != "synthetic-bao" {
		t.Fatal("wrong native environment")
	}
	if _, err := i.Logout(context.Background(), request.Identity); err != nil {
		t.Fatal(err)
	}
	if _, err := i.Logout(context.Background(), request.Identity); err != nil {
		t.Fatal(err)
	}
	if len(requests) != 2 || requests[1] != "/v1/auth/token/revoke-self" {
		t.Fatal("lease lifecycle changed")
	}
}

func TestIdentityRejectsExpandedPoliciesAndRevokesBeforeError(t *testing.T) {
	for _, change := range []func(map[string]any){
		func(v map[string]any) { v["policies"] = []string{"root"} }, func(v map[string]any) { v["token_policies"] = []string{"default"} },
		func(v map[string]any) { v["identity_policies"] = []string{"default"} }, func(v map[string]any) { v["lease_duration"] = 901 },
		func(v map[string]any) { v["lease_duration"] = 0 }, func(v map[string]any) {
			v["policies"] = []string{"fixture-reader", "self-revoke", "self-revoke"}
		},
	} {
		auth := authResponse()
		change(auth)
		revoked := false
		i := identity{store: &memoryStore{values: map[string][]byte{}}, run: runner(frame()), client: &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
			if strings.HasSuffix(r.URL.Path, "revoke-self") {
				revoked = true
				return httpReply(204, nil), nil
			}
			return httpReply(200, map[string]any{"auth": auth}), nil
		})}}
		out := &stream{ctx: context.Background()}
		if i.Authenticate(identityRequest(t), out) == nil || !revoked || len(out.events) != 0 {
			t.Fatal("expanded lease escaped or cleanup missing")
		}
	}
}

func TestLogoutFailureIsNotRetriedAndDoesNotEchoResponse(t *testing.T) {
	for _, code := range []int{302, 403, 503} {
		state := &memoryStore{values: map[string][]byte{leaseKey: []byte(`{"token":"synthetic-bao","address":"https://openbao.example.invalid"}`)}}
		count := 0
		i := identity{store: state, client: &http.Client{Transport: transport(func(*http.Request) (*http.Response, error) {
			count++
			return httpReply(code, "synthetic-private-response"), nil
		})}}
		for range 2 {
			_, err := i.Logout(context.Background(), &pluginv1.IdentityRequest{Spec: identitySpec(t)})
			if err == nil || strings.Contains(err.Error(), "synthetic-") {
				t.Fatal("unconfirmed revocation accepted or disclosed")
			}
		}
		if count != 1 {
			t.Fatal("ambiguous revocation retried")
		}
	}
}

func TestLateLogoutOrFailedDeliveryRevokesWithoutCredentials(t *testing.T) {
	for _, mode := range []string{"logout", "send", "storage"} {
		proofs, revokes := 0, 0
		state := &memoryStore{values: map[string][]byte{}, failPut: mode == "storage"}
		i := identity{store: state, run: func(ctx context.Context, action string, consume func(sessionFrame) error) error {
			proofs++
			if mode == "logout" && proofs == 2 {
				return errors.New("closed session")
			}
			return runner(frame())(ctx, action, consume)
		}, client: &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
			if strings.HasSuffix(r.URL.Path, "revoke-self") {
				revokes++
				return httpReply(204, nil), nil
			}
			return httpReply(200, map[string]any{"auth": authResponse()}), nil
		})}}
		out := &stream{ctx: context.Background()}
		if mode == "send" {
			out.err = errors.New("canceled delivery")
		}
		if i.Authenticate(identityRequest(t), out) == nil || len(out.events) != 0 || revokes != 1 {
			t.Fatal("late credential escaped")
		}
	}
}

// This test binary doubles as a credential-free stand-in for the installed
// native client. It deliberately emits sensitive-looking synthetic diagnostics.
func TestMain(m *testing.M) {
	if os.Getenv("ATMOS_PLUGIN_MAGIC_COOKIE") == "atmos-native-plugin-v1" {
		runFixturePlugin()
		return
	}
	if os.Getenv("NATIVE_ACCESS_FIXTURE") == "1" {
		out := os.NewFile(3, "private-pipe")
		io.WriteString(os.Stdout, "synthetic-private-stdout")
		io.WriteString(os.Stderr, "synthetic-private-stderr")
		io.WriteString(out, os.Getenv("NATIVE_ACCESS_FRAME"))
		out.Close()
		if os.Getenv("NATIVE_ACCESS_EXIT") == "fail" {
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestNativeClientPipeFramingAndFailedExit(t *testing.T) {
	t.Setenv("NATIVE_ACCESS_FIXTURE", "1")
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		payload string
		fail    bool
		ok      bool
	}{
		{`{"done":true}`, false, true}, {`{"done":true,"unknown":"synthetic-private"}`, false, false},
		{`{"done":true}` + "\n" + `{"done":true}`, false, false}, {`{"done":false}`, false, false}, {`not json`, false, false}, {`{"done":true}`, true, false},
	} {
		t.Setenv("NATIVE_ACCESS_FRAME", test.payload)
		t.Setenv("NATIVE_ACCESS_EXIT", "")
		if test.fail {
			t.Setenv("NATIVE_ACCESS_EXIT", "fail")
		}
		err := runSessionProcess(context.Background(), path, "atmos-oidc", os.Environ(), func(sessionFrame) error { return nil })
		if (err == nil) != test.ok {
			t.Fatal("client protocol admission changed")
		}
		if err != nil && strings.Contains(err.Error(), "synthetic-private") {
			t.Fatal("client diagnostic disclosed")
		}
	}
}
