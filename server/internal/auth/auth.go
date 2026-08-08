package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"slices"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"

	"sftp-proxy/internal/config"
)

// errAuthFailed is what every failure becomes on the way out to the SSH layer.
// A client learns only that authentication failed; the reason stays inside.
var errAuthFailed = errors.New("authentication failed")

type Session struct {
	User   config.User
	Client *http.Client
}

// Authenticator holds the configuration shared by every connection. It carries
// no per-connection state; that lives in Conn.
type Authenticator struct {
	config config.Config
}

// Conn is the authentication state for one SSH connection. It owns the cookie
// jar shared by that connection's authentication and filesystem requests, and
// the backend that jar is bound to.
//
// A Conn is created by the connection's goroutine and referenced only by the
// ssh.ServerConfig callbacks for that connection, so its lifetime is the
// socket's: when the connection goes away, so does the jar. Nothing needs to be
// swept, and there is no shared map to grow.
//
// Conn is not safe for concurrent use. It does not need to be: x/crypto/ssh
// dispatches one connection's auth callbacks sequentially from that
// connection's handshake goroutine.
type Conn struct {
	auth   *Authenticator
	client *http.Client

	// backend is nil when no authBackend is configured, which leaves the static
	// users in the config file as the only way in.
	backend backend
}

// backend is one authentication backend, bound to one connection. The two
// implementations are the two mutually exclusive shapes config allows:
// fullAuth for authBackend.baseURL and simpleAuth for authBackend.url.
//
// Both report the authenticated user on success. Neither sees the static users
// from the config file; Conn resolves those first and only reaches a backend
// for names the config file does not define.
type backend interface {
	Password(connection ssh.ConnMetadata, password []byte) (config.User, error)
	PublicKey(connection ssh.ConnMetadata, key ssh.PublicKey) (config.User, error)
}

func New(cfg config.Config) *Authenticator {
	return &Authenticator{config: cfg}
}

// NewConn starts authentication state for one SSH connection. The caller owns
// the result and must not share it between connections.
func (a *Authenticator) NewConn() *Conn {
	client := newClient()
	return &Conn{auth: a, client: client, backend: newBackend(a.config.AuthBackend, client)}
}

// newBackend selects the implementation for the configured backend. Config
// validation guarantees exactly one of url and baseURL is set, so the choice
// here is total.
func newBackend(cfg *config.AuthBackend, client *http.Client) backend {
	switch {
	case cfg == nil:
		return nil
	case cfg.URL != "":
		return &simpleAuth{backendClient{cfg: cfg, http: client}}
	default:
		return &fullAuth{backendClient: backendClient{cfg: cfg, http: client}}
	}
}

func (c *Conn) Password(connection ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	if user, found := c.auth.config.StaticUser(connection.User()); found {
		if user.PasswordHash == "" || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), password) != nil {
			return nil, errAuthFailed
		}
		return c.permissions(user), nil
	}
	if c.backend == nil {
		return nil, errAuthFailed
	}
	user, err := c.backend.Password(connection, password)
	if err != nil {
		return nil, errAuthFailed
	}
	return c.permissions(user), nil
}

func (c *Conn) PublicKey(connection ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	if user, found := c.auth.config.StaticUser(connection.User()); found {
		if !user.HasAuthorizedKey(key) {
			return nil, errAuthFailed
		}
		return c.permissions(user), nil
	}
	if c.backend == nil {
		return nil, errAuthFailed
	}
	user, err := c.backend.PublicKey(connection, key)
	if err != nil {
		return nil, errAuthFailed
	}
	return c.permissions(user), nil
}

// permissions hands the connection's client to the filesystem layer, so the
// cookie jar built during authentication carries into the SFTP session.
func (c *Conn) permissions(user config.User) *ssh.Permissions {
	return &ssh.Permissions{ExtraData: map[any]any{sessionKey{}: Session{User: user, Client: c.client}}}
}

type sessionKey struct{}

func SessionFrom(permissions *ssh.Permissions) (Session, bool) {
	if permissions == nil {
		return Session{}, false
	}
	session, found := permissions.ExtraData[sessionKey{}].(Session)
	return session, found
}

// simpleAuth implements authBackend.url: one endpoint that takes the password
// and connection metadata and answers with the user, in a single POST.
type simpleAuth struct {
	backendClient
}

func (a *simpleAuth) Password(connection ssh.ConnMetadata, password []byte) (config.User, error) {
	var result finalizeResponse
	err := a.postTo(connection, a.cfg.URL, request{
		Connection: fromConnection(connection),
		Password:   string(password),
		Method:     "password",
	}, &result)
	if err != nil {
		return config.User{}, err
	}
	return userFromResponse(connection, result)
}

// PublicKey always fails. This mode has no lookup step, so a backend has no way
// to publish a user's authorized keys and the server has nothing to check a key
// against. DESIGN.md: authBackend.url "does not offer public-key
// authentication."
func (a *simpleAuth) PublicKey(ssh.ConnMetadata, ssh.PublicKey) (config.User, error) {
	return config.User{}, errors.New("public-key authentication is not offered in single-endpoint mode")
}

// fullAuth implements authBackend.baseURL: a lookup that publishes the methods
// and keys allowed for the user, a per-method endpoint, and a finalize that
// answers with the user.
type fullAuth struct {
	backendClient

	// lookup caches the policy the backend returned for lookedUpUser, so the
	// repeated auth callbacks of one handshake need only one lookup POST. SSH
	// lets a client change the user name between auth requests, so a cached
	// policy is only valid for the name it was fetched under.
	lookedUpUser string
	lookup       *lookupResponse
}

func (a *fullAuth) Password(connection ssh.ConnMetadata, password []byte) (config.User, error) {
	lookup, err := a.lookupPolicy(connection)
	if err != nil {
		return config.User{}, err
	}
	if !slices.Contains(lookup.Methods, "password") {
		return config.User{}, errors.New("password authentication is not allowed for this user")
	}
	payload := request{Connection: fromConnection(connection), Password: string(password)}
	if err := a.post(connection, "password", payload, nil); err != nil {
		return config.User{}, err
	}
	return a.finalize(connection, "password", "")
}

func (a *fullAuth) PublicKey(connection ssh.ConnMetadata, key ssh.PublicKey) (config.User, error) {
	lookup, err := a.lookupPolicy(connection)
	if err != nil {
		return config.User{}, err
	}
	if !slices.Contains(lookup.Methods, "publickey") {
		return config.User{}, errors.New("public-key authentication is not allowed for this user")
	}
	if !matchesKey(lookup.AuthorizedKeys, key) {
		return config.User{}, errors.New("public key is not authorized for this user")
	}
	return a.finalize(connection, "publickey", ssh.FingerprintSHA256(key))
}

// lookupPolicy returns the backend's policy for the user this connection is
// currently authenticating as, fetching it on first use.
func (a *fullAuth) lookupPolicy(connection ssh.ConnMetadata) (*lookupResponse, error) {
	if a.lookup != nil && a.lookedUpUser == connection.User() {
		return a.lookup, nil
	}

	var lookup lookupResponse
	if err := a.post(connection, "lookup", request{Connection: fromConnection(connection)}, &lookup); err != nil {
		return nil, err
	}
	if len(lookup.Methods) == 0 {
		return nil, errors.New("backend offered no authentication methods")
	}
	a.lookedUpUser, a.lookup = connection.User(), &lookup
	return a.lookup, nil
}

func (a *fullAuth) finalize(connection ssh.ConnMetadata, method, fingerprint string) (config.User, error) {
	var result finalizeResponse
	err := a.post(connection, "finalize", request{
		Connection:  fromConnection(connection),
		Method:      method,
		Fingerprint: fingerprint,
	}, &result)
	if err != nil {
		return config.User{}, err
	}
	return userFromResponse(connection, result)
}

// post sends to one of the baseURL-relative endpoints.
func (a *fullAuth) post(connection ssh.ConnMetadata, endpoint string, payload request, target any) error {
	rawURL, err := endpointURL(a.cfg.BaseURL, endpoint)
	if err != nil {
		return err
	}
	return a.postTo(connection, rawURL, payload, target)
}

// backendClient is the HTTP plumbing both backends share: one POST of a request
// document to the backend, carrying the connection's cookie jar.
type backendClient struct {
	cfg  *config.AuthBackend
	http *http.Client
}

func (b *backendClient) postTo(connection ssh.ConnMetadata, rawURL string, payload request, target any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	// A hung backend must not pin the SSH handshake, so every auth POST — send,
	// response, and decode — runs under one bounded context. The bound is
	// per-request rather than an http.Client.Timeout because this same client is
	// handed to the filesystem afterwards, where transfers may run much longer.
	ctx := context.Background()
	if timeout := b.cfg.RequestTimeout(); timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	addForwardedHeaders(httpRequest, connection)
	response, err := b.http.Do(httpRequest)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("backend rejected authentication with status %d", response.StatusCode)
	}
	if target == nil {
		return nil
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

// userFromResponse applies the checks a backend-supplied user must pass before
// it can become a session: the backend may not answer with a different user
// than the one being authenticated, and the rootfs it returns must satisfy the
// same rules the config file does.
func userFromResponse(connection ssh.ConnMetadata, result finalizeResponse) (config.User, error) {
	user := result.User
	if user.Username == "" {
		user.Username = connection.User()
	}
	if user.Username != connection.User() {
		return config.User{}, fmt.Errorf("backend returned user %q for %q", user.Username, connection.User())
	}
	if err := user.RootFS.Validate(); err != nil {
		return config.User{}, fmt.Errorf("backend returned an invalid rootfs: %w", err)
	}
	return user, nil
}

type lookupResponse struct {
	Methods        []string `json:"methods"`
	AuthorizedKeys []string `json:"authorizedKeys"`
}

type finalizeResponse struct {
	User config.User `json:"user"`
}

type metadata struct {
	Username      string `json:"username"`
	RemoteAddress string `json:"remoteAddress"`
	LocalAddress  string `json:"localAddress"`
	ClientVersion string `json:"clientVersion"`
	ServerVersion string `json:"serverVersion"`
}

type request struct {
	Connection  metadata `json:"connection"`
	Password    string   `json:"password,omitempty"`
	Method      string   `json:"method,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
}

func endpointURL(baseURL, endpoint string) (string, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	// Join rather than replace: a baseURL may carry a path prefix the backend
	// needs, so https://api.example.com/sftp must resolve to
	// https://api.example.com/sftp/v1/sftp/auth/lookup.
	joined := parsed.JoinPath("v1", "sftp", "auth", endpoint)
	joined.RawQuery = ""
	joined.Fragment = ""
	return joined.String(), nil
}

func newClient() *http.Client {
	jar, err := cookiejar.New(nil)
	if err != nil {
		panic(err)
	}
	return &http.Client{Jar: jar}
}

func fromConnection(connection ssh.ConnMetadata) metadata {
	return metadata{
		Username:      connection.User(),
		RemoteAddress: connection.RemoteAddr().String(),
		LocalAddress:  connection.LocalAddr().String(),
		ClientVersion: string(connection.ClientVersion()),
		ServerVersion: string(connection.ServerVersion()),
	}
}

func addForwardedHeaders(request *http.Request, connection ssh.ConnMetadata) {
	host, _, err := net.SplitHostPort(connection.RemoteAddr().String())
	if err != nil {
		host = connection.RemoteAddr().String()
	}
	request.Header.Set("X-Forwarded-For", host)
	request.Header.Set("X-Forwarded-Proto", "ssh")
	request.Header.Set("X-Forwarded-Host", connection.LocalAddr().String())
}

func matchesKey(encodedKeys []string, key ssh.PublicKey) bool {
	return slices.ContainsFunc(encodedKeys, func(encoded string) bool {
		candidate, _, _, _, err := ssh.ParseAuthorizedKey([]byte(encoded))
		return err == nil && string(candidate.Marshal()) == string(key.Marshal())
	})
}
