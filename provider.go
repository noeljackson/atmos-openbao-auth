package main

import (
	"context"
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

type provider struct {
	pluginv1.UnimplementedAuthProviderServer
	open func(context.Context, string) error
	run  sessionRunner
}

func invalid() error {
	return status.Error(codes.InvalidArgument, "native authentication contract rejected")
}
func unavailable() error {
	return status.Error(codes.Unauthenticated, "workstation authentication unavailable; use explicit Atmos auth login")
}

func (*provider) Validate(_ context.Context, request *pluginv1.ProviderRequest) (*pluginv1.ValidateResponse, error) {
	if _, err := parseProvider(request.GetSpec()); err != nil {
		return nil, err
	}
	return &pluginv1.ValidateResponse{}, nil
}

func (p *provider) Authenticate(request *pluginv1.ProviderRequest, stream grpc.ServerStreamingServer[pluginv1.AuthenticateEvent]) error {
	ctx := api.WithInvocation(stream.Context(), request.GetInvocation().GetId())
	config, err := parseProvider(request.GetSpec())
	if err != nil {
		return err
	}
	// Component operations only reuse the existing workstation session. Native
	// interactive login/exec without a component may start that same authority.
	action := "atmos-oidc"
	invocation := request.GetInvocation()
	if config.LoginMethod != "existing" && invocation.GetInteractive() && invocation.GetStack() == "" && invocation.GetComponent() == "" {
		action = "atmos-login"
		if config.LoginMethod == "device" {
			action = "atmos-login-device"
		}
	}
	var result *pluginv1.Credentials
	run := p.run
	if run == nil {
		run = sessionClient(config.SessionClient)
	}
	err = run(ctx, action, func(frame sessionFrame) error {
		if frame.Prompt != nil {
			if action == "atmos-oidc" || frame.Done || frame.Credential != "" || frame.AccessToken != "" ||
				frame.Prompt.Device != (config.LoginMethod == "device") || !validPrompt(*frame.Prompt, config.Issuer) {
				return invalid()
			}
			if !frame.Prompt.Device {
				return p.open(ctx, frame.Prompt.URL)
			}
			return stream.Send(&pluginv1.AuthenticateEvent{Event: &pluginv1.AuthenticateEvent_Interaction{Interaction: &pluginv1.Interaction{
				Kind: "device_code", Title: "Approve Infrastructure CLI login",
				Fields: map[string]string{"verification_uri": frame.Prompt.URL, "user_code": frame.Prompt.Code},
			}}})
		}
		if result != nil || !frame.Done || frame.Issuer != config.Issuer || frame.ClientID != config.ClientID || frame.Subject != config.Subject ||
			frame.Credential == "" || len(frame.Credential) > 32768 || frame.AccessToken == "" || len(frame.AccessToken) > 32768 {
			return invalid()
		}
		expiry, err := time.Parse(time.RFC3339, frame.ExpiresAt)
		if err != nil || !expiry.After(time.Now()) {
			return invalid()
		}
		accessExpiry, err := time.Parse(time.RFC3339, frame.AccessExpiresAt)
		if err != nil || !accessExpiry.After(time.Now()) {
			return invalid()
		}
		if accessExpiry.Before(expiry) {
			expiry = accessExpiry
		}
		data, err := structpb.NewStruct(map[string]any{
			"issuer": frame.Issuer, "client_id": frame.ClientID, "subject": frame.Subject,
			"id_token": frame.Credential, "id_token_expires_at": frame.ExpiresAt,
			"access_token": frame.AccessToken, "token_type": "Bearer", "access_token_expires_at": frame.AccessExpiresAt,
		})
		if err != nil {
			return invalid()
		}
		result = &pluginv1.Credentials{Type: "oidc/v1", Data: data, ExpiresAt: timestamppb.New(expiry), SensitiveKeys: []string{"access_token", "id_token"}}
		return nil
	})
	if err != nil {
		return unavailable()
	}
	if result == nil {
		return invalid()
	}
	return stream.Send(&pluginv1.AuthenticateEvent{Event: &pluginv1.AuthenticateEvent_Result{Result: result}})
}

func (p *provider) Logout(ctx context.Context, request *pluginv1.ProviderRequest) (*emptypb.Empty, error) {
	config, err := parseProvider(request.GetSpec())
	if err != nil {
		return nil, err
	}
	run := p.run
	if run == nil {
		run = sessionClient(config.SessionClient)
	}
	err = run(ctx, "atmos-logout", func(frame sessionFrame) error {
		if !frame.Done || frame.Prompt != nil || frame.Credential != "" || frame.AccessToken != "" {
			return invalid()
		}
		return nil
	})
	if err != nil {
		return nil, unavailable()
	}
	return &emptypb.Empty{}, nil
}
