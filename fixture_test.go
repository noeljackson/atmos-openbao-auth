package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/cloudposse/atmos/sdk/api"
	"github.com/cloudposse/atmos/sdk/plugin"
	pluginv1 "github.com/cloudposse/atmos/sdk/proto/atmos/plugin/v1"
	"google.golang.org/grpc"
)

// Compiled only into the test executable. The production provider/identity
// implementations are unchanged; their external session and HTTP boundaries
// are replaced with a synthetic session and a loopback authority.
func runFixturePlugin() {
	executable, err := os.Executable()
	if err != nil {
		panic("fixture executable unavailable")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(executable), ".fixture-backend"))
	if err != nil {
		panic("fixture authority unavailable")
	}
	backend, err := url.Parse(strings.TrimSpace(string(raw)))
	if err != nil || backend.Scheme != "http" || net.ParseIP(backend.Hostname()) == nil || !net.ParseIP(backend.Hostname()).IsLoopback() {
		panic("invalid loopback fixture")
	}
	directory := filepath.Dir(executable)
	mode := "existing"
	if raw, err := os.ReadFile(filepath.Join(directory, ".fixture-mode")); err == nil {
		mode = strings.TrimSpace(string(raw))
	}
	switch mode {
	case "existing", "browser", "device", "device-cancel", "device-query", "device-extra":
	default:
		panic("invalid fixture mode")
	}
	plugin.Main(plugin.Config{Description: pluginDescription(), Build: func(client *api.Client) plugin.Services {
		fakeSession := fixtureSession(directory, mode)
		local := &http.Client{Transport: transport(func(request *http.Request) (*http.Response, error) {
			if request.URL.Host != "openbao.example.invalid" {
				return nil, errors.New("unexpected fixture authority")
			}
			forward := request.Clone(request.Context())
			target := *request.URL
			target.Scheme, target.Host = backend.Scheme, backend.Host
			forward.URL = &target
			return http.DefaultTransport.RoundTrip(forward)
		})}
		return plugin.Services{
			Provider: &fixtureProvider{provider: &provider{run: fakeSession, open: client.Open}, mode: mode},
			Identity: &identity{store: client, client: local, run: fakeSession},
		}
	}})
}

func fixtureSession(directory, mode string) sessionRunner {
	return func(ctx context.Context, action string, consume func(sessionFrame) error) error {
		approved := filepath.Join(directory, ".fixture-approved")
		if mode == "existing" {
			if action != "atmos-oidc" {
				return errors.New("fixture forbids approval")
			}
			value := frame()
			if marker, err := os.ReadFile(filepath.Join(directory, ".fixture-session-change")); err == nil {
				if string(marker) == "logout" {
					return errors.New("synthetic session closed during exchange")
				}
				value.Credential = "synthetic-refreshed-id"
			}
			return consume(value)
		}
		if _, err := os.Stat(approved); err == nil {
			return consume(frame())
		}
		device := strings.HasPrefix(mode, "device")
		if (device && action != "atmos-login-device") || (!device && action != "atmos-login") {
			return errors.New("fixture session requires explicit login")
		}
		prompt := &sessionPrompt{URL: "https://issuer.example.invalid/oauth/v2/authorize?state=synthetic-state"}
		if device {
			prompt = &sessionPrompt{Device: true, URL: "https://issuer.example.invalid/device", Code: "ABCD-EFGH"}
		}
		if mode == "device-query" {
			prompt.URL += "?token=synthetic-private-query"
		}
		if err := consume(sessionFrame{Prompt: prompt}); err != nil {
			return err
		}
		if mode == "device-cancel" {
			<-ctx.Done()
			return ctx.Err()
		}
		if err := os.WriteFile(approved, []byte("synthetic approval\n"), 0o600); err != nil {
			return err
		}
		return consume(frame())
	}
}

type fixtureProvider struct {
	*provider
	mode string
}

func (p *fixtureProvider) Authenticate(request *pluginv1.ProviderRequest, stream grpc.ServerStreamingServer[pluginv1.AuthenticateEvent]) error {
	return p.provider.Authenticate(request, &fixturePresentationStream{ServerStreamingServer: stream, mode: p.mode})
}

type fixturePresentationStream struct {
	grpc.ServerStreamingServer[pluginv1.AuthenticateEvent]
	mode string
}

func (s *fixturePresentationStream) Send(event *pluginv1.AuthenticateEvent) error {
	if prompt := event.GetInteraction(); prompt != nil {
		prompt.Title = "synthetic-private-title"
		if s.mode == "device-extra" {
			prompt.Fields["debug"] = "synthetic-private-debug"
		}
		if err := s.ServerStreamingServer.Send(&pluginv1.AuthenticateEvent{Event: &pluginv1.AuthenticateEvent_Progress{Progress: &pluginv1.Progress{Message: "synthetic-private-progress"}}}); err != nil {
			return err
		}
	}
	return s.ServerStreamingServer.Send(event)
}
