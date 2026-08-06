package auth

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sync"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"

	"sftp-proxy/internal/config"
)

type Session struct {
	User   config.User
	Client *http.Client
}

type Authenticator struct {
	config   config.Config
	attempts sync.Map
}

type attempt struct {
	client *http.Client
	lookup lookupResponse
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

func (a *Authenticator) Password(connection ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	if user, found := a.config.StaticUser(connection.User()); found {
		if user.PasswordHash == "" || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), password) != nil {
			return nil, errors.New("authentication failed")
		}
		return permissions(user, newClient()), nil
	}
	if a.config.AuthBackend != nil && a.config.AuthBackend.URL != "" {
		return a.singleEndpointPassword(connection, password)
	}

	attempt, err := a.lookup(connection)
	if err != nil || !allows(attempt.lookup.Methods, "password") {
		return nil, errors.New("authentication failed")
	}
	if err := a.post(connection, attempt.client, "password", request{Connection: fromConnection(connection), Password: string(password)}, nil); err != nil {
		return nil, errors.New("authentication failed")
	}
	return a.finalize(connection, attempt.client, "password", "")
}

func (a *Authenticator) singleEndpointPassword(connection ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	client := newClient()
	var result finalizeResponse
	if err := a.postToURL(connection, client, a.config.AuthBackend.URL, request{
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
	return permissions(result.User, client), nil
}

func (a *Authenticator) PublicKey(connection ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	if user, found := a.config.StaticUser(connection.User()); found {
		if !user.HasAuthorizedKey(key) {
			return nil, errors.New("authentication failed")
		}
		return permissions(user, newClient()), nil
	}

	attempt, err := a.lookup(connection)
	if err != nil || !allows(attempt.lookup.Methods, "publickey") || !matchesKey(attempt.lookup.AuthorizedKeys, key) {
		return nil, errors.New("authentication failed")
	}
	return a.finalize(connection, attempt.client, "publickey", ssh.FingerprintSHA256(key))
}

func SessionFrom(permissions *ssh.Permissions) (Session, bool) {
	if permissions == nil {
		return Session{}, false
	}
	session, found := permissions.ExtraData[sessionKey{}].(Session)
	return session, found
}

func (a *Authenticator) lookup(connection ssh.ConnMetadata) (*attempt, error) {
	if a.config.AuthBackend == nil {
		return nil, errors.New("no authentication backend")
	}
	id := string(connection.SessionID())
	if existing, found := a.attempts.Load(id); found {
		return existing.(*attempt), nil
	}

	client := newClient()
	var lookup lookupResponse
	if err := a.post(connection, client, "lookup", request{Connection: fromConnection(connection)}, &lookup); err != nil || len(lookup.Methods) == 0 {
		return nil, errors.New("authentication lookup failed")
	}
	created := &attempt{client: client, lookup: lookup}
	actual, loaded := a.attempts.LoadOrStore(id, created)
	if loaded {
		return actual.(*attempt), nil
	}
	return created, nil
}

func (a *Authenticator) finalize(connection ssh.ConnMetadata, client *http.Client, method, fingerprint string) (*ssh.Permissions, error) {
	defer a.attempts.Delete(string(connection.SessionID()))
	var result finalizeResponse
	if err := a.post(connection, client, "finalize", request{
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
	return permissions(result.User, client), nil
}

func (a *Authenticator) post(connection ssh.ConnMetadata, client *http.Client, endpoint string, payload request, target any) error {
	endpointURL, err := endpointURL(a.config.AuthBackend.BaseURL, endpoint)
	if err != nil {
		return err
	}
	return a.postToURL(connection, client, endpointURL, payload, target)
}

func (a *Authenticator) postToURL(connection ssh.ConnMetadata, client *http.Client, rawURL string, payload request, target any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	httpRequest, err := http.NewRequest(http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	addForwardedHeaders(httpRequest, connection)
	requestClient := *client
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
	parsed.Path = "/v1/sftp/auth/" + endpoint
	parsed.RawQuery = ""
	return parsed.String(), nil
}

func newClient() *http.Client {
	jar, err := cookiejar.New(nil)
	if err != nil {
		panic(err)
	}
	return &http.Client{Jar: jar}
}

func permissions(user config.User, client *http.Client) *ssh.Permissions {
	return &ssh.Permissions{ExtraData: map[any]any{sessionKey{}: Session{User: user, Client: client}}}
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
