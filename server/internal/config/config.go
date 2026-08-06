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

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
)

type Config struct {
	Schema           string       `json:"$schema,omitempty"`
	HostKeyFile      string       `json:"hostKeyFile"`
	Port             int          `json:"port"`
	UploadStagingDir string       `json:"uploadStagingDir"`
	AuthBackend      *AuthBackend `json:"authBackend,omitempty"`
	Users            []User       `json:"users,omitempty"`
}

type AuthBackend struct {
	BaseURL string `json:"baseURL"`
	URL     string `json:"url,omitempty"`
}

type User struct {
	Username       string   `json:"username"`
	PasswordHash   string   `json:"passwordHash,omitempty"`
	AuthorizedKeys []string `json:"authorizedKeys,omitempty"`
	RootFS         RootFS   `json:"rootfs"`
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
