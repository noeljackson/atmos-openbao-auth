package main

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"net/http"
	"syscall"
	"time"

	"github.com/cloudposse/atmos/sdk/api"
	"github.com/cloudposse/atmos/sdk/plugin"
	pluginv1 "github.com/cloudposse/atmos/sdk/proto/atmos/plugin/v1"
	"gopkg.in/yaml.v3"
)

const pluginName = "noeljackson/openbao-auth"

//go:embed plugin.yaml
var manifestData []byte

func main() {
	if syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{}) != nil {
		panic("process hardening failed")
	}
	plugin.Main(plugin.Config{
		Description: pluginDescription(),
		Build: func(client *api.Client) plugin.Services {
			httpClient := *client.HTTPClient()
			httpClient.Timeout = 30 * time.Second
			httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			return plugin.Services{Provider: &provider{open: client.Open}, Identity: &identity{store: client, client: &httpClient}}
		},
	})
}

func pluginDescription() *pluginv1.DescribeResponse {
	var metadata struct {
		Metadata struct {
			Version string `yaml:"version"`
		} `yaml:"metadata"`
	}
	if yaml.Unmarshal(manifestData, &metadata) != nil {
		panic("invalid embedded plugin manifest")
	}
	digest := sha256.Sum256(manifestData)
	return &pluginv1.DescribeResponse{
		PluginName: pluginName, PluginVersion: metadata.Metadata.Version,
		ManifestDigest: "sha256:" + hex.EncodeToString(digest[:]),
		Services:       []*pluginv1.ServiceVersionRange{{Service: "auth.provider", Min: 1, Max: 1}, {Service: "auth.identity", Min: 1, Max: 1}},
		Exports:        []*pluginv1.Export{{Service: "auth.provider", Kind: "noeljackson/oidc-session"}, {Service: "auth.identity", Kind: "noeljackson/openbao"}},
	}
}
