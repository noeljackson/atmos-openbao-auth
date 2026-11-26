package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/cloudposse/atmos/sdk/api"
	pluginv1 "github.com/cloudposse/atmos/sdk/proto/atmos/plugin/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const leaseKey = "openbao-lease/v1"

type privateStore interface {
	Get(context.Context, string) ([]byte, bool, error)
	Put(context.Context, string, []byte) error
	Delete(context.Context, string) error
}
type identity struct {
	pluginv1.UnimplementedAuthIdentityServer
	store  privateStore
	client *http.Client
	run    sessionRunner
}
type baoLease struct {
	Token         string `json:"token"`
	Address       string `json:"address"`
	RevokeStarted bool   `json:"revoke_started"`
}

func (*identity) Validate(_ context.Context, request *pluginv1.IdentityRequest) (*pluginv1.ValidateResponse, error) {
	if _, err := parseIdentity(request.GetSpec()); err != nil {
		return nil, err
	}
	return &pluginv1.ValidateResponse{}, nil
}

func (i *identity) Authenticate(request *pluginv1.IdentityAuthenticateRequest, stream grpc.ServerStreamingServer[pluginv1.AuthenticateEvent]) (resultErr error) {
	ctx := api.WithInvocation(stream.Context(), request.GetIdentity().GetInvocation().GetId())
	config, err := parseIdentity(request.GetIdentity().GetSpec())
	if err != nil {
		return err
	}
	upstream := request.GetUpstream()
	fields := upstream.GetData().GetFields()
	expiry, err := time.Parse(time.RFC3339, fields["id_token_expires_at"].GetStringValue())
	if err != nil || upstream.GetType() != "oidc/v1" || upstream.GetExpiresAt() == nil || upstream.GetExpiresAt().CheckValid() != nil ||
		!upstream.GetExpiresAt().AsTime().After(time.Now()) || !expiry.After(time.Now()) ||
		fields["issuer"].GetStringValue() != config.Issuer || fields["client_id"].GetStringValue() != config.ClientID || fields["subject"].GetStringValue() != config.Subject {
		return invalid()
	}
	jwt := fields["id_token"].GetStringValue()
	if jwt == "" || len(jwt) > 32768 {
		return invalid()
	}
	if i.checkSession(ctx, config, jwt) != nil {
		return unavailable()
	}
	// Each store operation requires a fresh lease. An unfinished earlier lease
	// is never silently reused or overwritten.
	if _, found, err := i.store.Get(ctx, leaseKey); err != nil || found {
		return unavailable()
	}
	input, err := json.Marshal(map[string]string{"role": config.Role, "jwt": jwt})
	if err != nil {
		return invalid()
	}
	if ctx.Err() != nil {
		return unavailable()
	}
	// Once issuance starts, keep custody of a returned token after cancellation
	// so it can be revoked. The exchange is bounded independently of shutdown.
	issueCtx, cancelIssue := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancelIssue()
	requestHTTP, err := http.NewRequestWithContext(issueCtx, http.MethodPost, config.Address+"/v1/auth/"+config.AuthPath+"/login", bytes.NewReader(input))
	if err != nil {
		return invalid()
	}
	requestHTTP.Header.Set("Content-Type", "application/json")
	started := time.Now()
	response, err := i.client.Do(requestHTTP)
	if err != nil {
		return unavailable()
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return unavailable()
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(raw) > 65536 {
		return unavailable()
	}
	var envelope struct {
		Auth json.RawMessage `json:"auth"`
	}
	if json.Unmarshal(raw, &envelope) != nil {
		return unavailable()
	}
	var token struct {
		Token string `json:"client_token"`
	}
	if json.Unmarshal(envelope.Auth, &token) != nil || !validBaoToken(token.Token) {
		return unavailable()
	}
	lease := baoLease{Token: token.Token, Address: config.Address}
	committed, stored := false, false
	defer func() {
		if !committed {
			if err := i.cleanupLease(ctx, lease, stored); err != nil {
				resultErr = err
			}
		}
	}()
	var auth struct {
		Policies         []string `json:"policies"`
		TokenPolicies    []string `json:"token_policies"`
		IdentityPolicies []string `json:"identity_policies"`
		Lease            int      `json:"lease_duration"`
	}
	if json.Unmarshal(envelope.Auth, &auth) != nil || auth.Lease < 1 || auth.Lease > config.MaxTTLSeconds || len(auth.IdentityPolicies) != 0 ||
		!exactPolicies(auth.Policies, config.ExpectedPolicies) || !exactPolicies(auth.TokenPolicies, config.ExpectedPolicies) {
		return invalid()
	}
	// Logout or refresh while the exchange was in flight fences delivery. A
	// changed ID token fails closed; this exchange is never automatically retried.
	leaseExpiry := started.Add(time.Duration(auth.Lease) * time.Second)
	if expiry.Before(leaseExpiry) {
		leaseExpiry = expiry
	}
	if upstream.GetExpiresAt().AsTime().Before(leaseExpiry) {
		leaseExpiry = upstream.GetExpiresAt().AsTime()
	}
	if ctx.Err() != nil || !leaseExpiry.After(time.Now()) || i.checkSession(ctx, config, jwt) != nil {
		return unavailable()
	}
	saved, err := json.Marshal(lease)
	if err != nil || i.store.Put(ctx, leaseKey, saved) != nil {
		return unavailable()
	}
	stored = true
	if ctx.Err() != nil || !leaseExpiry.After(time.Now()) {
		return unavailable()
	}
	data, err := structpb.NewStruct(map[string]any{"VAULT_TOKEN": lease.Token})
	if err != nil {
		return invalid()
	}
	result := &pluginv1.Credentials{Type: "environment/v1", Data: data,
		ExpiresAt: timestamppb.New(leaseExpiry), SensitiveKeys: []string{"VAULT_TOKEN"}}
	if err := stream.Send(&pluginv1.AuthenticateEvent{Event: &pluginv1.AuthenticateEvent_Result{Result: result}}); err != nil {
		return unavailable()
	}
	committed = true
	return nil
}

func (i *identity) checkSession(ctx context.Context, config identitySettings, jwt string) error {
	if config.SessionClient == "" {
		return nil
	}
	run := i.run
	if run == nil {
		run = sessionClient(config.SessionClient)
	}
	seen := false
	err := run(ctx, "atmos-oidc", func(frame sessionFrame) error {
		if seen || !frame.Done || frame.Prompt != nil || frame.Issuer != config.Issuer || frame.ClientID != config.ClientID || frame.Subject != config.Subject ||
			subtle.ConstantTimeCompare([]byte(frame.Credential), []byte(jwt)) != 1 {
			return invalid()
		}
		expiry, err := time.Parse(time.RFC3339, frame.ExpiresAt)
		if err != nil || !expiry.After(time.Now()) {
			return invalid()
		}
		seen = true
		return nil
	})
	if err != nil || !seen {
		return unavailable()
	}
	return nil
}

func revocationUnconfirmed() error {
	return status.Error(codes.FailedPrecondition, "OpenBao revocation unconfirmed; credential dispatch forbidden")
}

func exactPolicies(actual, expected []string) bool {
	actual = slices.Clone(actual)
	expected = slices.Clone(expected)
	slices.Sort(actual)
	slices.Sort(expected)
	return slices.Equal(actual, expected)
}

func (i *identity) revoke(ctx context.Context, address, token string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, address+"/v1/auth/token/revoke-self", nil)
	if err != nil {
		return unavailable()
	}
	request.Header.Set("X-Vault-Token", token)
	response, err := i.client.Do(request)
	if err != nil {
		return unavailable()
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return unavailable()
	}
	return nil
}

// Keep failed revocation marked in private storage so an uncertain request
// cannot be repeated automatically. One deadline covers the whole teardown.
func (i *identity) cleanupLease(ctx context.Context, lease baoLease, stored bool) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if stored {
		lease.RevokeStarted = true
		raw, err := json.Marshal(lease)
		if err != nil || i.store.Put(ctx, leaseKey, raw) != nil {
			return revocationUnconfirmed()
		}
	}
	if i.revoke(ctx, lease.Address, lease.Token) != nil {
		return revocationUnconfirmed()
	}
	if stored && i.store.Delete(ctx, leaseKey) != nil {
		return unavailable()
	}
	return nil
}

func (i *identity) Logout(ctx context.Context, request *pluginv1.IdentityRequest) (*emptypb.Empty, error) {
	ctx = api.WithInvocation(ctx, request.GetInvocation().GetId())
	config, err := parseIdentity(request.GetSpec())
	if err != nil {
		return nil, err
	}
	raw, found, err := i.store.Get(ctx, leaseKey)
	if err != nil {
		return nil, unavailable()
	}
	if !found {
		return &emptypb.Empty{}, nil
	}
	var lease baoLease
	if json.Unmarshal(raw, &lease) != nil || !validBaoToken(lease.Token) || lease.Address != config.Address || lease.RevokeStarted {
		return nil, revocationUnconfirmed()
	}
	if err := i.cleanupLease(ctx, lease, true); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}
