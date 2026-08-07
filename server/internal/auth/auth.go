package auth

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"

	"sftp-proxy/internal/config"
)

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
// caches the backend's lookup response so the repeated auth callbacks of one
// handshake need only one lookup POST.
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

	// lookup caches the policy the backend returned for lookedUpUser. SSH lets a
	// client change the user name between auth requests, so a cached policy is
	// only valid for the name it was fetched under.
	lookedUpUser string
	lookup       *lookupResponse
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

type sessionKey struct{}

func New(cfg config.Config) *Authenticator {
	return &Authenticator{config: cfg}
}

// NewConn starts authentication state for one SSH connection. The caller owns
// the result and must not share it between connections.
func (a *Authenticator) NewConn() *Conn {
	return &Conn{auth: a, client: newClient()}
}

func (c *Conn) Password(connection ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	if user, found := c.auth.config.StaticUser(connection.User()); found {
		if user.PasswordHash == "" || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), password) != nil {
			return nil, errors.New("authentication failed")
		}
		return c.permissions(user), nil
	}
	if c.auth.config.AuthBackend != nil && c.auth.config.AuthBackend.URL != "" {
		return c.singleEndpointPassword(connection, password)
	}

	lookup, err := c.lookupPolicy(connection)
	if err != nil || !allows(lookup.Methods, "password") {
		return nil, errors.New("authentication failed")
	}
	if err := c.post(connection, "password", request{Connection: fromConnection(connection), Password: string(password)}, nil); err != nil {
		return nil, errors.New("authentication failed")
	}
	return c.finalize(connection, "password", "")
}

func (c *Conn) singleEndpointPassword(connection ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	var result finalizeResponse
	if err := c.postToURL(connection, c.auth.config.AuthBackend.URL, request{
		Connection: fromConnection(connection),
		Password:   string(password),
		Method:     "password",
	}, &result); err != nil {
		return nil, errors.New("authentication failed")
	}
	if result.User.Username == "" {
		result.User.Username = connection.User()
	}
	if result.User.Username != connection.User() || result.User.RootFS.Validate() != nil {
		return nil, errors.New("authentication failed")
	}
	return c.permissions(result.User), nil
}

func (c *Conn) PublicKey(connection ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	if user, found := c.auth.config.StaticUser(connection.User()); found {
		if !user.HasAuthorizedKey(key) {
			return nil, errors.New("authentication failed")
		}
		return c.permissions(user), nil
	}

	lookup, err := c.lookupPolicy(connection)
	if err != nil || !allows(lookup.Methods, "publickey") || !matchesKey(lookup.AuthorizedKeys, key) {
		return nil, errors.New("authentication failed")
	}
	return c.finalize(connection, "publickey", ssh.FingerprintSHA256(key))
}

func SessionFrom(permissions *ssh.Permissions) (Session, bool) {
	if permissions == nil {
		return Session{}, false
	}
	session, found := permissions.ExtraData[sessionKey{}].(Session)
	return session, found
}

// lookupPolicy returns the backend's policy for the user this connection is
// currently authenticating as, fetching it on first use.
func (c *Conn) lookupPolicy(connection ssh.ConnMetadata) (*lookupResponse, error) {
	if c.auth.config.AuthBackend == nil {
		return nil, errors.New("no authentication backend")
	}
	if c.lookup != nil && c.lookedUpUser == connection.User() {
		return c.lookup, nil
	}

	var lookup lookupResponse
	if err := c.post(connection, "lookup", request{Connection: fromConnection(connection)}, &lookup); err != nil || len(lookup.Methods) == 0 {
		return nil, errors.New("authentication lookup failed")
	}
	c.lookedUpUser, c.lookup = connection.User(), &lookup
	return c.lookup, nil
}

func (c *Conn) finalize(connection ssh.ConnMetadata, method, fingerprint string) (*ssh.Permissions, error) {
	var result finalizeResponse
	if err := c.post(connection, "finalize", request{
		Connection:  fromConnection(connection),
		Method:      method,
		Fingerprint: fingerprint,
	}, &result); err != nil {
		return nil, errors.New("authentication failed")
	}
	if result.User.Username == "" {
		result.User.Username = connection.User()
	}
	if result.User.Username != connection.User() || result.User.RootFS.Validate() != nil {
		return nil, errors.New("authentication failed")
	}
	return c.permissions(result.User), nil
}

func (c *Conn) post(connection ssh.ConnMetadata, endpoint string, payload request, target any) error {
	endpointURL, err := endpointURL(c.auth.config.AuthBackend.BaseURL, endpoint)
	if err != nil {
		return err
	}
	return c.postToURL(connection, endpointURL, payload, target)
}

func (c *Conn) postToURL(connection ssh.ConnMetadata, rawURL string, payload request, target any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	// A hung backend must not pin the SSH handshake, so every auth POST — send,
	// response, and decode — runs under one bounded context. The bound is
	// per-request rather than an http.Client.Timeout because this same client is
	// handed to the filesystem afterwards, where transfers may run much longer.
	ctx := context.Background()
	if timeout := c.auth.config.AuthBackend.RequestTimeout(); timeout > 0 {
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
	requestClient := *c.client
	requestClient.CheckRedirect = sameOriginRedirect(httpRequest.URL)
	response, err := requestClient.Do(httpRequest)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return errors.New("backend rejected authentication")
	}
	if target == nil {
		return nil
	}
	decoder := json.NewDecoder(http.MaxBytesReader(nil, response.Body, 1<<20))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

func sameOriginRedirect(origin *url.URL) func(*http.Request, []*http.Request) error {
	return func(request *http.Request, _ []*http.Request) error {
		if request.URL.Scheme != origin.Scheme || request.URL.Host != origin.Host {
			return http.ErrUseLastResponse
		}
		return nil
	}
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

// permissions hands the connection's client to the filesystem layer, so the
// cookie jar built during authentication carries into the SFTP session.
func (c *Conn) permissions(user config.User) *ssh.Permissions {
	return &ssh.Permissions{ExtraData: map[any]any{sessionKey{}: Session{User: user, Client: c.client}}}
}

func fromConnection(connection ssh.ConnMetadata) metadata {
	return metadata{connection.User(), connection.RemoteAddr().String(), connection.LocalAddr().String(), string(connection.ClientVersion()), string(connection.ServerVersion())}
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

func allows(methods []string, method string) bool {
	for _, allowed := range methods {
		if allowed == method {
			return true
		}
	}
	return false
}

func matchesKey(encodedKeys []string, key ssh.PublicKey) bool {
	for _, encoded := range encodedKeys {
		candidate, _, _, _, err := ssh.ParseAuthorizedKey([]byte(encoded))
		if err == nil && subtle.ConstantTimeCompare(candidate.Marshal(), key.Marshal()) == 1 {
			return true
		}
	}
	return false
}
