package main

import (
	"context"
	"encoding/json"
	"io"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Frames never enter a diagnostic. Only the native provider converts their
// sensitive payload into an Atmos credential envelope.
type sessionPrompt struct {
	URL    string `json:"url"`
	Code   string `json:"code"`
	Device bool   `json:"device"`
}
type sessionFrame struct {
	Prompt          *sessionPrompt `json:"prompt"`
	Done            bool           `json:"done"`
	Issuer          string         `json:"issuer"`
	ClientID        string         `json:"client_id"`
	Subject         string         `json:"subject"`
	Credential      string         `json:"credential"`
	ExpiresAt       string         `json:"expires_at"`
	AccessToken     string         `json:"access_token"`
	AccessExpiresAt string         `json:"access_token_expires_at"`
}
type sessionRunner func(context.Context, string, func(sessionFrame) error) error

func validPrompt(prompt sessionPrompt, issuer string) bool {
	u, err := url.Parse(prompt.URL)
	root, rootErr := url.Parse(issuer)
	return err == nil && len(prompt.URL) <= 8192 && len(prompt.Code) <= 256 && u.Scheme == "https" &&
		rootErr == nil && strings.EqualFold(u.Host, root.Host) && u.User == nil && u.Fragment == "" &&
		(!prompt.Device || (prompt.Code != "" && u.RawQuery == ""))
}

func sessionClient(path string) sessionRunner {
	return func(ctx context.Context, action string, consume func(sessionFrame) error) error {
		return runSession(ctx, path, action, consume)
	}
}

func runSession(ctx context.Context, path, action string, consume func(sessionFrame) error) error {
	switch action {
	case "atmos-oidc", "atmos-login", "atmos-login-device", "atmos-logout":
	default:
		return invalid()
	}
	account, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil || !filepath.IsAbs(account.HomeDir) {
		return unavailable()
	}
	if !sessionClientPath(path) {
		return unavailable()
	}
	if strings.HasPrefix(path, "~/") {
		path = filepath.Join(account.HomeDir, strings.TrimPrefix(path, "~/"))
	}
	if validateSessionExecutable(path) != nil {
		return unavailable()
	}
	environment := []string{"HOME=" + account.HomeDir, "PATH=/usr/bin:/bin"}
	if runtime.GOOS == "linux" {
		directory := "/run/user/" + strconv.Itoa(os.Getuid())
		environment = append(environment, "XDG_RUNTIME_DIR="+directory, "DBUS_SESSION_BUS_ADDRESS=unix:path="+directory+"/bus")
	}
	return runSessionProcess(ctx, path, action, environment, consume)
}

func validateSessionExecutable(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Mode().Perm()&0o100 == 0 {
		return unavailable()
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) {
		return unavailable()
	}
	return nil
}

// The executable is the fixed installed native client. No shell is used; FD3
// is the only output transport. Cancellation closes the client and its login.
func runSessionProcess(ctx context.Context, path, action string, environment []string, consume func(sessionFrame) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	read, write, err := os.Pipe()
	if err != nil {
		return unavailable()
	}
	defer read.Close()
	defer write.Close()
	command := exec.CommandContext(ctx, path, action)
	command.Env = append([]string(nil), environment...)
	command.Stdin, command.Stdout, command.Stderr = nil, io.Discard, io.Discard
	command.ExtraFiles = []*os.File{write}
	command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
	command.WaitDelay = 5 * time.Second
	if command.Start() != nil {
		return unavailable()
	}
	write.Close()
	limited := &io.LimitedReader{R: read, N: 128*1024 + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	done, failed := false, false
	for {
		var frame sessionFrame
		err := decoder.Decode(&frame)
		if err == io.EOF {
			break
		}
		if err != nil || done || consume(frame) != nil {
			failed = true
			cancel()
			break
		}
		done = frame.Done
	}
	if !done || limited.N == 0 {
		failed = true
		cancel()
	}
	err = command.Wait()
	if failed || err != nil || ctx.Err() != nil {
		return unavailable()
	}
	return nil
}
