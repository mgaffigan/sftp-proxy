package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
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
	BindAddress      string       `json:"bindAddress,omitempty"`
	UploadStagingDir string       `json:"uploadStagingDir"`
	LoginGraceMs     *Millis      `json:"loginGraceMs,omitempty"`
	AuthBackend      *AuthBackend `json:"authBackend,omitempty"`
	FileBackend      *FileBackend `json:"fileBackend,omitempty"`
	S3Backend        *S3Backend   `json:"s3Backend,omitempty"`
	Users            []User       `json:"users,omitempty"`
}

type AuthBackend struct {
	BaseURL   string  `json:"baseURL"`
	URL       string  `json:"url,omitempty"`
	TimeoutMs *Millis `json:"timeoutMs,omitempty"`
}

// FileBackend is a deployment's consent to serve local files. Its absence
// withholds the file scheme entirely, so a file:// entry cannot be reached
// however a configuration or a backend listing names it.
type FileBackend struct {
	AllowedPrefixes []string `json:"allowedPrefixes"`
}

// S3Backend is a deployment's consent to serve S3 objects. Its absence withholds
// the s3 scheme entirely, as leaving fileBackend out withholds file.
//
// Its buckets are the credentials a deployment holds itself, for the buckets it
// knows about when it starts. A deployment serving tenants it cannot enumerate
// leaves the list empty and lets each entry carry its own credentials instead.
type S3Backend struct {
	Buckets []S3Bucket `json:"buckets,omitempty"`
}

// S3Access is how one bucket is reached. An entry may carry it inline, which is
// what lets a directory name a bucket this deployment has never heard of: the
// backend that returned the entry already holds those credentials, so stating
// them says nothing it did not already know.
type S3Access struct {
	Region          string `json:"region,omitempty"`
	Endpoint        string `json:"endpoint,omitempty"`
	PathStyle       *bool  `json:"pathStyle,omitempty"`
	AccessKeyID     string `json:"accessKeyId,omitempty"`
	SecretAccessKey string `json:"secretAccessKey,omitempty"`
	SessionToken    string `json:"sessionToken,omitempty"`
}

// S3Bucket names a bucket in the configuration file's own table, and is the one
// place the proxy's ambient identity can be asked for. S3Access, which is what a
// backend may send, has no such field: a directory listing therefore cannot ask
// the proxy to spend credentials of its own.
type S3Bucket struct {
	S3Access
	Bucket                string `json:"bucket"`
	UseDefaultCredentials bool   `json:"useDefaultCredentials,omitempty"`
}

// LogValue keeps the secret out of anything that logs an access. Nothing in this
// proxy logs one today; this is so that adding such a line cannot spill a key.
func (a S3Access) LogValue() slog.Value {
	credentials := "none"
	if a.AccessKeyID != "" {
		credentials = "[redacted]"
	}
	return slog.GroupValue(
		slog.String("region", a.Region),
		slog.String("endpoint", a.Endpoint),
		slog.String("credentials", credentials),
	)
}

// UsePathStyle reports whether requests address the bucket in the URL path
// rather than in the hostname. AWS uses virtual-host addressing; most anything
// else running at a fixed endpoint does not, so an endpoint that states nothing
// gets path style.
func (a S3Access) UsePathStyle() bool {
	if a.PathStyle != nil {
		return *a.PathStyle
	}
	return a.Endpoint != ""
}

// Bucket finds a configured bucket's access. A deployment that configured none
// is not an error here: the entry that named the bucket may carry its own.
func (s *S3Backend) Bucket(name string) (S3Bucket, bool) {
	if s == nil {
		return S3Bucket{}, false
	}
	for _, bucket := range s.Buckets {
		if bucket.Bucket == name {
			return bucket, true
		}
	}
	return S3Bucket{}, false
}

type User struct {
	Username             string   `json:"username"`
	PasswordHash         string   `json:"passwordHash,omitempty"`
	AuthorizedKeys       []string `json:"authorizedKeys,omitempty"`
	ClientAliveMs        Millis   `json:"clientAliveMs,omitempty"`
	ClientAliveCountMax  *int     `json:"clientAliveCountMax,omitempty"`
	MaxConcurrentUploads int      `json:"maxConcurrentUploads,omitempty"`
	RootFS               RootFS   `json:"rootfs"`
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

func (u User) UploadConcurrencyLimit() int {
	return max(u.MaxConcurrentUploads, 0)
}

type RootFS struct {
	Backend        string    `json:"backend,omitempty"`
	AllowedMethods []string  `json:"allowedMethods,omitempty"`
	Permissions    *uint32   `json:"permissions,omitempty"`
	S3             *S3Access `json:"s3,omitempty"`
	Children       []Entry   `json:"children,omitempty"`
	MaxUploadSize  int64     `json:"maxUploadSize,omitempty"`
}

// Entry views the root as the directory node it is, so that resolution,
// listing, and method checks treat it no differently from any other directory.
func (r RootFS) Entry() Entry {
	return Entry{
		Directory:      "/",
		Backend:        r.Backend,
		AllowedMethods: r.AllowedMethods,
		Permissions:    r.Permissions,
		S3:             r.S3,
		Children:       r.Children,
		MaxUploadSize:  r.MaxUploadSize,
	}
}

type Entry struct {
	Directory      string     `json:"directory,omitempty"`
	File           string     `json:"file,omitempty"`
	Backend        string     `json:"backend,omitempty"`
	AllowedMethods []string   `json:"allowedMethods,omitempty"`
	Size           int64      `json:"size,omitempty"`
	Mtime          *time.Time `json:"mtime,omitempty"`
	Permissions    *uint32    `json:"permissions,omitempty"`
	S3             *S3Access  `json:"s3,omitempty"`
	Children       []Entry    `json:"children,omitempty"`
	MaxUploadSize  int64      `json:"maxUploadSize,omitempty"`
}

func Load(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("read configuration: %w", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
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
	if c.FileBackend != nil {
		if err := c.FileBackend.Validate(); err != nil {
			return fmt.Errorf("fileBackend: %w", err)
		}
	}
	if c.S3Backend != nil {
		if err := c.S3Backend.Validate(); err != nil {
			return fmt.Errorf("s3Backend: %w", err)
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
		if err := c.validateLocalPaths(user.RootFS); err != nil {
			return fmt.Errorf("users[%d]: %w", index, err)
		}
		if err := c.validateS3Buckets(user.RootFS); err != nil {
			return fmt.Errorf("users[%d]: %w", index, err)
		}
		if _, exists := seenUsers[user.Username]; exists {
			return fmt.Errorf("duplicate username %q", user.Username)
		}
		seenUsers[user.Username] = struct{}{}
	}
	return nil
}

func (f FileBackend) Validate() error {
	if len(f.AllowedPrefixes) == 0 {
		return errors.New("allowedPrefixes requires at least one directory")
	}
	for index, prefix := range f.AllowedPrefixes {
		if !filepath.IsAbs(prefix) || filepath.Clean(prefix) != prefix {
			return fmt.Errorf("allowedPrefixes[%d]: %q must be an absolute, cleaned path", index, prefix)
		}
		// A path lying under two prefixes would be served through whichever was
		// found first, and which prefix serves it decides how far a symlink
		// inside it may reach. Overlap is rejected so that is never a question.
		for _, other := range f.AllowedPrefixes[:index] {
			if _, inside := Relative(other, prefix); inside {
				return fmt.Errorf("allowedPrefixes[%d]: %q overlaps %q", index, prefix, other)
			}
			if _, inside := Relative(prefix, other); inside {
				return fmt.Errorf("allowedPrefixes[%d]: %q overlaps %q", index, prefix, other)
			}
		}
	}
	return nil
}

// Relative reports where path lies within prefix, and whether it lies there at
// all: it may be prefix itself or anything beneath it. Components are compared
// whole, so /srv/data does not contain /srv/database, and a path that climbs
// back out is not inside. Both must be absolute and cleaned.
//
// This is the one definition of that question. What may be served rests on it,
// so a second one that disagreed would be a way in.
func Relative(prefix, path string) (string, bool) {
	relative, err := filepath.Rel(prefix, path)
	if err != nil || relative != "." && !filepath.IsLocal(relative) {
		return "", false
	}
	return relative, true
}

// validateLocalPaths refuses at startup what the file backend would refuse at
// request time: a local path this deployment has not consented to serve. Only a
// statically configured tree can be checked here — one a user's authentication
// backend supplies arrives too late — so the backend enforces this again itself.
func (c Config) validateLocalPaths(root RootFS) error {
	return walkEntries(root, func(entry Entry) error {
		return c.validateLocalBackend(entry.Backend)
	})
}

// validateS3Buckets refuses at startup an S3 bucket this deployment can neither
// reach with credentials of its own nor was told how to reach. As above, only a
// statically configured tree can be checked here, so the backend checks again.
func (c Config) validateS3Buckets(root RootFS) error {
	return walkEntries(root, func(entry Entry) error {
		return c.validateS3Backend(entry.Backend, entry.S3)
	})
}

// walkEntries visits the root and every entry beneath it, naming in any error
// where the offending entry was found.
func walkEntries(root RootFS, visit func(entry Entry) error) error {
	var walk func(entry Entry) error
	walk = func(entry Entry) error {
		if err := visit(entry); err != nil {
			return fmt.Errorf("%s: %w", entry.Name(), err)
		}
		for _, child := range entry.Children {
			if err := walk(child); err != nil {
				return err
			}
		}
		return nil
	}
	if err := visit(root.Entry()); err != nil {
		return fmt.Errorf("rootfs: %w", err)
	}
	for _, child := range root.Children {
		if err := walk(child); err != nil {
			return fmt.Errorf("rootfs: %w", err)
		}
	}
	return nil
}

func (c Config) validateLocalBackend(rawURL string) error {
	path, ok := LocalPath(rawURL)
	if !ok {
		return nil
	}
	if c.FileBackend == nil {
		return errors.New("a file backend URL requires fileBackend.allowedPrefixes")
	}
	for _, prefix := range c.FileBackend.AllowedPrefixes {
		if _, inside := Relative(prefix, path); inside {
			return nil
		}
	}
	return fmt.Errorf("%q lies outside every fileBackend.allowedPrefixes entry", path)
}

func (c Config) validateS3Backend(rawURL string, access *S3Access) error {
	bucket, _, ok := S3Location(rawURL)
	if !ok {
		return nil
	}
	if c.S3Backend == nil {
		return errors.New("an s3 backend URL requires s3Backend")
	}
	// An entry stating its own credentials names a bucket this deployment need
	// never have heard of, which is the whole point of stating them.
	if access != nil {
		return nil
	}
	if _, found := c.S3Backend.Bucket(bucket); !found {
		return fmt.Errorf("bucket %q is not in s3Backend.buckets and the entry states no credentials", bucket)
	}
	return nil
}

func (s S3Backend) Validate() error {
	for index, bucket := range s.Buckets {
		if err := bucket.Validate(); err != nil {
			return fmt.Errorf("buckets[%d]: %w", index, err)
		}
		for _, other := range s.Buckets[:index] {
			if other.Bucket == bucket.Bucket {
				return fmt.Errorf("buckets[%d]: duplicate bucket %q", index, bucket.Bucket)
			}
		}
	}
	return nil
}

func (b S3Bucket) Validate() error {
	if !ValidBucketName(b.Bucket) {
		return fmt.Errorf("invalid bucket name %q", b.Bucket)
	}
	// The two ways to hold credentials are alternatives, not layers: a bucket
	// asking for both would leave which one signs a request unanswered.
	if b.UseDefaultCredentials {
		if b.AccessKeyID != "" || b.SecretAccessKey != "" || b.SessionToken != "" {
			return errors.New("useDefaultCredentials cannot be combined with an access key")
		}
		return b.validateReachable()
	}
	return b.S3Access.Validate()
}

// Validate checks an access stated inline on an entry, where credentials are
// required: an entry that has none says nothing the bucket table did not
// already say, and omitting it says exactly that.
func (a S3Access) Validate() error {
	if err := a.validateReachable(); err != nil {
		return err
	}
	if a.AccessKeyID == "" || a.SecretAccessKey == "" {
		return errors.New("accessKeyId and secretAccessKey are both required")
	}
	return nil
}

// validateReachable checks what says where a bucket is, leaving what signs for
// it to the caller: a configuration file may name the proxy's own identity
// instead of a key, and an entry may not.
func (a S3Access) validateReachable() error {
	if a.Region == "" {
		return errors.New("region is required")
	}
	if a.Endpoint == "" {
		return nil
	}
	parsed, err := url.Parse(a.Endpoint)
	if err != nil || parsed.Host == "" || parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("endpoint must be an http or https URL, got %q", a.Endpoint)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("endpoint must not contain credentials, a query, or a fragment")
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
	if !ValidName(u.Username) {
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
	if u.MaxConcurrentUploads < 0 {
		return errors.New("maxConcurrentUploads cannot be negative")
	}
	return u.RootFS.Validate()
}

func (r RootFS) Validate() error {
	if r.MaxUploadSize < 0 {
		return errors.New("upload limit cannot be negative")
	}
	if r.Backend != "" {
		if err := validateBackendURL(r.Backend); err != nil {
			return err
		}
	}
	if err := validateMethods(r.AllowedMethods, r.Backend); err != nil {
		return err
	}
	if err := validateAccess(r.S3, r.Backend); err != nil {
		return err
	}
	return validateChildren(r.Children, "rootfs")
}

// ValidateEntries checks a list of sibling entries, as returned by a backend
// directory listing.
func ValidateEntries(entries []Entry) error {
	return validateChildren(entries, "listing")
}

func validateChildren(children []Entry, location string) error {
	seenNames := make(map[string]struct{}, len(children))
	for index, child := range children {
		if err := child.Validate(); err != nil {
			return fmt.Errorf("%s.children[%d]: %w", location, index, err)
		}
		name := child.Name()
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
	if !ValidName(e.Name()) {
		return fmt.Errorf("invalid entry name %q", e.Name())
	}
	if e.Size < 0 || e.MaxUploadSize < 0 {
		return errors.New("file size and upload limit cannot be negative")
	}
	if e.Permissions != nil && *e.Permissions > 0777 {
		return errors.New("permissions must contain only permission bits")
	}
	if e.File != "" {
		if e.Backend == "" {
			return errors.New("file entries require a backend")
		}
		if len(e.Children) != 0 {
			return errors.New("file entries cannot have children")
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
	if err := validateMethods(e.AllowedMethods, e.Backend); err != nil {
		return err
	}
	if err := validateAccess(e.S3, e.Backend); err != nil {
		return err
	}
	return validateChildren(e.Children, e.Name())
}

// IsDirectory reports the entry's kind. Exactly one of Directory and File is
// set, so naming one is naming both.
func (e Entry) IsDirectory() bool { return e.Directory != "" }

// Name is the entry's single path component, whichever kind it is.
func (e Entry) Name() string {
	if e.Directory != "" {
		return e.Directory
	}
	return e.File
}

func (c Config) StaticUser(username string) (User, bool) {
	for _, user := range c.Users {
		if user.Username == username {
			return user, true
		}
	}
	return User{}, false
}

func (u User) HasAuthorizedKey(key ssh.PublicKey) bool {
	for _, encodedKey := range u.AuthorizedKeys {
		candidate, _, _, _, err := ssh.ParseAuthorizedKey([]byte(encodedKey))
		if err == nil && string(candidate.Marshal()) == string(key.Marshal()) {
			return true
		}
	}
	return false
}

// supportedMethods is every HTTP method the proxy knows how to send to a
// backend, and so the only values allowedMethods may name.
var supportedMethods = []string{"GET", "POST", "DELETE"}

// validateMethods checks allowedMethods for a node served by backend.
// The list constrains the requests the proxy will send to that backend, so it
// is meaningless — and therefore rejected rather than silently ignored — on a
// node that has no backend to send them to, or on one served locally, where
// there is no request to withhold and permissions is the equivalent lever.
func validateMethods(methods []string, backend string) error {
	if len(methods) == 0 {
		return nil
	}
	if backend == "" {
		return errors.New("allowedMethods requires a backend")
	}
	if _, local := LocalPath(backend); local {
		return errors.New("allowedMethods does not apply to a file backend; use permissions")
	}
	if _, _, isS3 := S3Location(backend); isS3 {
		return errors.New("allowedMethods does not apply to an s3 backend; use permissions")
	}
	for index, method := range methods {
		if !slices.Contains(supportedMethods, method) {
			return fmt.Errorf("unsupported allowed method %q", method)
		}
		if slices.Contains(methods[:index], method) {
			return fmt.Errorf("duplicate allowed method %q", method)
		}
	}
	return nil
}

// ValidName reports whether name is one ordinary path component: a username, a
// configured entry, an entry from a backend listing, or a name a client asks to
// create. All of them answer to this, so a name that can be uploaded is a name a
// listing can carry back.
func ValidName(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "/\\\x00") && filepath.Base(name) == name
}

// FileScheme names the backend serving local files. A node's URL scheme selects
// its backend, so this is also the string a deployment withholds by leaving
// fileBackend out of its configuration.
const FileScheme = "file"

// S3Scheme names the backend serving S3 objects, withheld in the same way by a
// configuration that leaves s3Backend out.
const S3Scheme = "s3"

// validateAccess checks credentials stated on an entry. They constrain nothing
// without an s3:// backend to reach, so an entry carrying them anywhere else is
// rejected rather than quietly ignored — as allowedMethods is.
func validateAccess(access *S3Access, backend string) error {
	if access == nil {
		return nil
	}
	if _, _, ok := S3Location(backend); !ok {
		return errors.New("s3 credentials require an s3 backend URL")
	}
	return access.Validate()
}

func validateBackendURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" {
		return fmt.Errorf("invalid backend URL %q", rawURL)
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return errors.New("backend URL must not contain credentials or a fragment")
	}
	switch parsed.Scheme {
	case "http", "https":
		if parsed.Host == "" {
			return fmt.Errorf("invalid backend URL %q", rawURL)
		}
		return nil
	case FileScheme:
		if _, ok := LocalPath(rawURL); !ok {
			return fmt.Errorf("file backend URL must name a local absolute path and nothing else, got %q", rawURL)
		}
		return nil
	case S3Scheme:
		if _, _, ok := S3Location(rawURL); !ok {
			return fmt.Errorf("s3 backend URL must name a bucket and an object key and nothing else, got %q", rawURL)
		}
		return nil
	default:
		return fmt.Errorf("backend URL must use http, https, file, or s3, got %q", parsed.Scheme)
	}
}

// S3Location reports the bucket and object key an s3 backend URL names, and
// whether the URL is one at all. It is the single definition of what s3:// means
// to this proxy: a bucket as the host and an object key as the path, with
// nothing else attached.
//
// The key is returned without a leading slash, so a bucket root is the empty
// key. Every segment is an ordinary name, which is what keeps a key built here
// from climbing anywhere: there is no . or .. for it to climb with.
func S3Location(rawURL string) (bucket, key string, ok bool) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != S3Scheme {
		return "", "", false
	}
	if parsed.Opaque != "" || parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" || parsed.ForceQuery {
		return "", "", false
	}
	if !ValidBucketName(parsed.Host) {
		return "", "", false
	}
	segments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(segments) == 1 && segments[0] == "" {
		return parsed.Host, "", true
	}
	for _, segment := range segments {
		if !ValidName(segment) {
			return "", "", false
		}
	}
	return parsed.Host, strings.Join(segments, "/"), true
}

// ValidBucketName reports whether name is a bucket name every S3 implementation
// accepts: the common subset, rather than the widest any one of them allows.
// A name outside it is refused here rather than turned into a request that
// would be signed for one host and answered by another.
func ValidBucketName(name string) bool {
	if len(name) < 3 || len(name) > 63 || net.ParseIP(name) != nil {
		return false
	}
	for index, character := range []byte(name) {
		alphanumeric := character >= 'a' && character <= 'z' || character >= '0' && character <= '9'
		switch {
		case alphanumeric:
		case character != '-' && character != '.':
			return false
		case index == 0 || index == len(name)-1:
			return false
		case name[index-1] == '.' || name[index-1] == '-':
			return false
		}
	}
	return true
}

// LocalPath reports the filesystem path a file backend URL names, and whether
// the URL is one at all. It is the single definition of what file:// means to
// this proxy: an absolute path on this host, with nothing else attached.
//
// The path is cleaned but otherwise unexamined. Whether it may be served, and
// whether following it stays where it should, is settled where the operation
// happens rather than by inspecting the string.
func LocalPath(rawURL string) (string, bool) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != FileScheme {
		return "", false
	}
	// RFC 8089 lets the local host be named or left out; anything else names a
	// host this backend cannot reach.
	if parsed.Host != "" && parsed.Host != "localhost" {
		return "", false
	}
	if parsed.Opaque != "" || parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" || parsed.ForceQuery {
		return "", false
	}
	if !strings.HasPrefix(parsed.Path, "/") {
		return "", false
	}
	return filepath.Clean(filepath.FromSlash(parsed.Path)), true
}
