package config

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
)

// Defaults for the tunables below. The two with an sshd_config(5) counterpart
// use its default; DefaultAuthBackendTimeout has no OpenSSH analogue.
const (
	DefaultLoginGrace          = 120 * time.Second
	DefaultClientAliveCountMax = 3
	DefaultAuthBackendTimeout  = 30 * time.Second
)

// Millis is a duration configured in milliseconds. Settings that take one are
// pointers so an omitted value can take its default while an explicit 0 keeps
// the OpenSSH meaning of "no limit".
type Millis int

func (m Millis) Duration() time.Duration {
	return time.Duration(m) * time.Millisecond
}

type Config struct {
	Schema           string       `json:"$schema,omitempty"`
	HostKeyFile      string       `json:"hostKeyFile"`
	Port             int          `json:"port"`
	UploadStagingDir string       `json:"uploadStagingDir"`
	LoginGraceMs     *Millis      `json:"loginGraceMs,omitempty"`
	AuthBackend      *AuthBackend `json:"authBackend,omitempty"`
	Users            []User       `json:"users,omitempty"`
}

type AuthBackend struct {
	BaseURL   string  `json:"baseURL"`
	URL       string  `json:"url,omitempty"`
	TimeoutMs *Millis `json:"timeoutMs,omitempty"`
}

type User struct {
	Username            string   `json:"username"`
	PasswordHash        string   `json:"passwordHash,omitempty"`
	AuthorizedKeys      []string `json:"authorizedKeys,omitempty"`
	ClientAliveMs       Millis   `json:"clientAliveMs,omitempty"`
	ClientAliveCountMax *int     `json:"clientAliveCountMax,omitempty"`
	RootFS              RootFS   `json:"rootfs"`
}

// LoginGrace reports how long a connection may take to authenticate, after
// which it is disconnected. Zero means no limit. Server-wide, because it
// applies before there is a user to consult.
func (c Config) LoginGrace() time.Duration {
	if c.LoginGraceMs == nil {
		return DefaultLoginGrace
	}
	return c.LoginGraceMs.Duration()
}

// RequestTimeout bounds one HTTP request to the authentication backend. Zero
// means no limit.
func (a *AuthBackend) RequestTimeout() time.Duration {
	if a == nil || a.TimeoutMs == nil {
		return DefaultAuthBackendTimeout
	}
	return a.TimeoutMs.Duration()
}

// ClientAlive reports the post-authentication liveness policy: how long the
// session may be idle before the server probes the client, and how many
// consecutive unanswered probes end the connection. A zero interval disables
// probing entirely; a zero count never terminates on a missed probe. Both match
// ClientAliveInterval and ClientAliveCountMax in sshd_config(5).
//
// A User may come from an authentication backend rather than the config file,
// where Validate does not run over these fields, so negatives are clamped here
// rather than trusted.
func (u User) ClientAlive() (interval time.Duration, countMax int) {
	countMax = DefaultClientAliveCountMax
	if u.ClientAliveCountMax != nil {
		countMax = max(*u.ClientAliveCountMax, 0)
	}
	return max(u.ClientAliveMs.Duration(), 0), countMax
}

type RootFS struct {
	Children []Entry `json:"children"`
}

type Entry struct {
	Directory            string   `json:"directory,omitempty"`
	File                 string   `json:"file,omitempty"`
	Backend              string   `json:"backend,omitempty"`
	AllowedMethods       []string `json:"allowed_methods,omitempty"`
	Size                 int64    `json:"size,omitempty"`
	Children             []Entry  `json:"children,omitempty"`
	MaxUploadSize        int64    `json:"maxUploadSize,omitempty"`
	MaxConcurrentUploads int      `json:"maxConcurrentUploads,omitempty"`
}

func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read configuration: %w", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var cfg Config
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode configuration: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("decode configuration: multiple JSON values")
	}

	if cfg.Port == 0 {
		cfg.Port = 2222
	}
	if cfg.UploadStagingDir == "" {
		cfg.UploadStagingDir = "staging"
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if c.HostKeyFile == "" {
		return errors.New("hostKeyFile is required")
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535, got %d", c.Port)
	}
	if c.UploadStagingDir == "" {
		return errors.New("uploadStagingDir is required")
	}
	if c.LoginGraceMs != nil && *c.LoginGraceMs < 0 {
		return errors.New("loginGraceMs cannot be negative")
	}
	if c.AuthBackend != nil {
		if err := c.AuthBackend.Validate(); err != nil {
			return fmt.Errorf("authBackend: %w", err)
		}
	}
	if len(c.Users) == 0 && c.AuthBackend == nil {
		return errors.New("configure at least one user or authBackend")
	}

	seenUsers := make(map[string]struct{}, len(c.Users))
	for index, user := range c.Users {
		if err := user.Validate(); err != nil {
			return fmt.Errorf("users[%d]: %w", index, err)
		}
		if _, exists := seenUsers[user.Username]; exists {
			return fmt.Errorf("duplicate username %q", user.Username)
		}
		seenUsers[user.Username] = struct{}{}
	}
	return nil
}

func (a AuthBackend) Validate() error {
	if (a.BaseURL == "") == (a.URL == "") {
		return errors.New("exactly one of baseURL or url is required")
	}
	if a.TimeoutMs != nil && *a.TimeoutMs < 0 {
		return errors.New("timeoutMs cannot be negative")
	}
	if a.BaseURL != "" {
		return validateBackendURL(a.BaseURL)
	}
	return validateBackendURL(a.URL)
}

func (u User) Validate() error {
	if !validName(u.Username) {
		return fmt.Errorf("invalid username %q", u.Username)
	}
	if u.PasswordHash == "" && len(u.AuthorizedKeys) == 0 {
		return errors.New("passwordHash or authorizedKeys is required")
	}
	if u.PasswordHash != "" {
		if _, err := bcrypt.Cost([]byte(u.PasswordHash)); err != nil {
			return fmt.Errorf("invalid passwordHash: %w", err)
		}
	}
	for index, encodedKey := range u.AuthorizedKeys {
		if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(encodedKey)); err != nil {
			return fmt.Errorf("authorizedKeys[%d]: %w", index, err)
		}
	}
	if u.ClientAliveMs < 0 {
		return errors.New("clientAliveMs cannot be negative")
	}
	if u.ClientAliveCountMax != nil && *u.ClientAliveCountMax < 0 {
		return errors.New("clientAliveCountMax cannot be negative")
	}
	return u.RootFS.Validate()
}

func (r RootFS) Validate() error {
	return validateChildren(r.Children, "rootfs")
}

func validateChildren(children []Entry, location string) error {
	seenNames := make(map[string]struct{}, len(children))
	for index, child := range children {
		if err := child.Validate(); err != nil {
			return fmt.Errorf("%s.children[%d]: %w", location, index, err)
		}
		name := child.name()
		if _, exists := seenNames[name]; exists {
			return fmt.Errorf("%s contains duplicate entry %q", location, name)
		}
		seenNames[name] = struct{}{}
	}
	return nil
}

func (e Entry) Validate() error {
	if (e.Directory == "") == (e.File == "") {
		return errors.New("exactly one of directory or file is required")
	}
	if !validName(e.name()) {
		return fmt.Errorf("invalid entry name %q", e.name())
	}
	if e.Size < 0 || e.MaxUploadSize < 0 || e.MaxConcurrentUploads < 0 {
		return errors.New("file size and upload limits cannot be negative")
	}
	if e.File != "" {
		if e.Backend == "" {
			return errors.New("file entries require a backend")
		}
		if len(e.Children) != 0 {
			return errors.New("file entries cannot have children")
		}
		if len(e.AllowedMethods) != 0 {
			return errors.New("allowed_methods is only valid for directory entries")
		}
	}
	if e.Directory != "" && e.Backend == "" && len(e.Children) == 0 {
		return errors.New("directory entries require a backend or children")
	}
	if e.Backend != "" {
		if err := validateBackendURL(e.Backend); err != nil {
			return err
		}
	}
	seenMethods := make(map[string]struct{}, len(e.AllowedMethods))
	for _, method := range e.AllowedMethods {
		if method != "GET" && method != "POST" && method != "DELETE" {
			return fmt.Errorf("unsupported allowed method %q", method)
		}
		if _, exists := seenMethods[method]; exists {
			return fmt.Errorf("duplicate allowed method %q", method)
		}
		seenMethods[method] = struct{}{}
	}
	return validateChildren(e.Children, e.name())
}

func (e Entry) name() string {
	if e.Directory != "" {
		return e.Directory
	}
	return e.File
}

func (c Config) StaticUser(username string) (User, bool) {
	for _, user := range c.Users {
		if subtle.ConstantTimeCompare([]byte(user.Username), []byte(username)) == 1 {
			return user, true
		}
	}
	return User{}, false
}

func (u User) HasAuthorizedKey(key ssh.PublicKey) bool {
	for _, encodedKey := range u.AuthorizedKeys {
		candidate, _, _, _, err := ssh.ParseAuthorizedKey([]byte(encodedKey))
		if err == nil && subtle.ConstantTimeCompare(candidate.Marshal(), key.Marshal()) == 1 {
			return true
		}
	}
	return false
}

func validName(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "/\\\x00") && filepath.Base(name) == name
}

func validateBackendURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("invalid backend URL %q", rawURL)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("backend URL must use http or https, got %q", parsed.Scheme)
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return fmt.Errorf("backend URL must not contain credentials or a fragment")
	}
	return nil
}
