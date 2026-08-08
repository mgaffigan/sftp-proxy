package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"golang.org/x/crypto/ssh"

	"sftp-proxy/internal/config"
)

func TestPasswordAuthenticationCallsLookupThenPassword(t *testing.T) {
	var calls []string
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls = append(calls, request.URL.Path)
		switch request.URL.Path {
		case "/v1/sftp/auth/lookup":
			if request.Header.Get("X-Forwarded-For") != "192.0.2.10" {
				t.Fatalf("X-Forwarded-For = %q", request.Header.Get("X-Forwarded-For"))
			}
			http.SetCookie(writer, &http.Cookie{Name: "session", Value: "abc", Path: "/"})
			_ = json.NewEncoder(writer).Encode(lookupResponse{Methods: []string{"password"}})
		case "/v1/sftp/auth/password":
			if _, err := request.Cookie("session"); err != nil {
				t.Fatalf("password request did not retain cookie: %v", err)
			}
			_ = json.NewEncoder(writer).Encode(authResponse{User: config.User{RootFS: config.RootFS{Children: []config.Entry{{
				Directory: "Inbound",
				Backend:   "https://files.example.test/inbound",
			}}}}})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer backend.Close()

	authConn := New(config.Config{AuthBackend: &config.AuthBackend{BaseURL: backend.URL}}).NewConn(t.Context())
	permissions, err := authConn.Password(testConnection{username: "acme"}, []byte("not logged"))
	if err != nil {
		t.Fatalf("Password() error = %v", err)
	}
	session, found := SessionFrom(permissions)
	if !found || session.User.Username != "acme" || len(session.User.RootFS.Children) != 1 {
		t.Fatalf("unexpected session: %#v, found=%v", session, found)
	}
	if want := []string{"/v1/sftp/auth/lookup", "/v1/sftp/auth/password"}; !slices.Equal(calls, want) {
		t.Fatalf("backend calls = %v, want %v", calls, want)
	}
}

// authBackend.baseURL's public-key path calls lookup then publickey, never
// finalize, and finalize's old method field disambiguation is gone: publickey
// is reachable only via its own endpoint now.
func TestPublicKeyAuthenticationCallsLookupThenPublicKey(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	authorizedKey := string(ssh.MarshalAuthorizedKey(key))

	var calls []string
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls = append(calls, request.URL.Path)
		switch request.URL.Path {
		case "/v1/sftp/auth/lookup":
			_ = json.NewEncoder(writer).Encode(lookupResponse{Methods: []string{"publickey"}, AuthorizedKeys: []string{authorizedKey}})
		case "/v1/sftp/auth/publickey":
			body, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}
			var raw map[string]json.RawMessage
			if err := json.Unmarshal(body, &raw); err != nil {
				t.Fatal(err)
			}
			if _, hasMethod := raw["method"]; hasMethod {
				t.Fatalf("publickey request still sends a method field: %s", body)
			}
			var received struct {
				Connection  metadata `json:"connection"`
				Fingerprint string   `json:"fingerprint"`
			}
			if err := json.Unmarshal(body, &received); err != nil {
				t.Fatal(err)
			}
			if received.Connection.Username != "acme" || received.Fingerprint != ssh.FingerprintSHA256(key) {
				t.Fatalf("unexpected publickey request: %#v", received)
			}
			_ = json.NewEncoder(writer).Encode(authResponse{User: config.User{RootFS: config.RootFS{Children: []config.Entry{{
				Directory: "Inbound",
				Backend:   "https://files.example.test/inbound",
			}}}}})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer backend.Close()

	authConn := New(config.Config{AuthBackend: &config.AuthBackend{BaseURL: backend.URL}}).NewConn(t.Context())
	permissions, err := authConn.PublicKey(testConnection{username: "acme"}, key)
	if err != nil {
		t.Fatalf("PublicKey() error = %v", err)
	}
	session, found := SessionFrom(permissions)
	if !found || session.User.Username != "acme" || len(session.User.RootFS.Children) != 1 {
		t.Fatalf("unexpected session: %#v, found=%v", session, found)
	}
	if want := []string{"/v1/sftp/auth/lookup", "/v1/sftp/auth/publickey"}; !slices.Equal(calls, want) {
		t.Fatalf("backend calls = %v, want %v", calls, want)
	}
}

// authBackend.headers lets the proxy authenticate itself to the backend, on
// every request in both baseURL and single-endpoint mode since both funnel
// through backendClient.postTo.
func TestConfiguredHeadersAreSentToTheBackend(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("Authorization"); got != "Bearer secret" {
			t.Fatalf("Authorization = %q, want %q", got, "Bearer secret")
		}
		_ = json.NewEncoder(writer).Encode(lookupResponse{Methods: []string{"password"}})
	}))
	defer backend.Close()

	authConn := New(config.Config{AuthBackend: &config.AuthBackend{
		BaseURL: backend.URL,
		Headers: map[string]string{"Authorization": "Bearer secret"},
	}}).NewConn(t.Context())
	fullBackend, ok := authConn.backend.(*fullAuth)
	if !ok {
		t.Fatalf("backend = %T, want *fullAuth", authConn.backend)
	}
	if _, err := fullBackend.lookupPolicy(t.Context(), testConnection{username: "acme"}); err != nil {
		t.Fatalf("lookupPolicy() error = %v", err)
	}
}

func TestConfiguredHeadersAreSentToTheSingleEndpoint(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("Authorization"); got != "Bearer secret" {
			t.Fatalf("Authorization = %q, want %q", got, "Bearer secret")
		}
		_ = json.NewEncoder(writer).Encode(authResponse{User: config.User{RootFS: config.RootFS{Children: []config.Entry{{
			Directory: "Inbound",
			Backend:   "https://files.example.test/inbound",
		}}}}})
	}))
	defer backend.Close()

	authConn := New(config.Config{AuthBackend: &config.AuthBackend{
		URL:     backend.URL,
		Headers: map[string]string{"Authorization": "Bearer secret"},
	}}).NewConn(t.Context())
	if _, err := authConn.Password(testConnection{username: "acme"}, []byte("secret")); err != nil {
		t.Fatalf("Password() error = %v", err)
	}
}

func TestPasswordAuthenticationWithSingleEndpoint(t *testing.T) {
	var backend *httptest.Server
	backend = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, httpRequest *http.Request) {
		if httpRequest.URL.Path != "/auth" || httpRequest.Method != http.MethodPost {
			http.NotFound(writer, httpRequest)
			return
		}
		var received struct {
			Connection metadata `json:"connection"`
			Password   string   `json:"password"`
		}
		if err := json.NewDecoder(httpRequest.Body).Decode(&received); err != nil {
			t.Fatal(err)
		}
		if received.Connection.Username != "acme" || received.Password != "secret" {
			t.Fatalf("unexpected auth request: %#v", received)
		}
		_ = json.NewEncoder(writer).Encode(authResponse{User: config.User{RootFS: config.RootFS{Children: []config.Entry{{
			Directory: "Inbound",
			Backend:   backend.URL + "/upload",
		}}}}})
	}))
	defer backend.Close()

	authConn := New(config.Config{AuthBackend: &config.AuthBackend{URL: backend.URL + "/auth"}}).NewConn(t.Context())
	permissions, err := authConn.Password(testConnection{username: "acme"}, []byte("secret"))
	if err != nil {
		t.Fatalf("Password() error = %v", err)
	}
	if session, found := SessionFrom(permissions); !found || session.User.Username != "acme" {
		t.Fatalf("unexpected session: %#v, found=%v", session, found)
	}
}

func TestAuthenticationFollowsCrossOriginRedirects(t *testing.T) {
	var elsewhere *httptest.Server
	elsewhere = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			t.Errorf("redirected method = %s, want POST", request.Method)
		}
		_ = json.NewEncoder(writer).Encode(authResponse{User: config.User{RootFS: config.RootFS{Children: []config.Entry{{
			Directory: "Inbound",
			Backend:   elsewhere.URL + "/inbound",
		}}}}})
	}))
	defer elsewhere.Close()

	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, elsewhere.URL, http.StatusTemporaryRedirect)
	}))
	defer backend.Close()

	authConn := New(config.Config{AuthBackend: &config.AuthBackend{URL: backend.URL}}).NewConn(t.Context())
	permissions, err := authConn.Password(testConnection{username: "acme"}, []byte("secret"))
	if err != nil {
		t.Fatalf("Password() through a cross-origin redirect = %v", err)
	}
	if session, found := SessionFrom(permissions); !found || session.User.Username != "acme" {
		t.Fatalf("unexpected session: %#v, found=%v", session, found)
	}
}

// authBackend.url mode is password-only, so a public-key attempt must be
// rejected outright rather than reaching the backend.
func TestPublicKeyIsRejectedWithSingleEndpoint(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, httpRequest *http.Request) {
		t.Errorf("backend called for %s %s", httpRequest.Method, httpRequest.URL.Path)
		http.NotFound(writer, httpRequest)
	}))
	defer backend.Close()

	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}

	authConn := New(config.Config{AuthBackend: &config.AuthBackend{URL: backend.URL + "/auth"}}).NewConn(t.Context())
	if _, ok := authConn.backend.(*simpleAuth); !ok {
		t.Fatalf("backend = %T, want *simpleAuth", authConn.backend)
	}
	if _, err := authConn.PublicKey(testConnection{username: "acme"}, key); err == nil {
		t.Fatal("PublicKey() succeeded in single-endpoint mode, want failure")
	}
}

func TestEndpointURLPreservesBasePath(t *testing.T) {
	cases := []struct {
		baseURL string
		want    string
	}{
		{"https://api.example.com", "https://api.example.com/v1/sftp/auth/lookup"},
		{"https://api.example.com/", "https://api.example.com/v1/sftp/auth/lookup"},
		{"https://api.example.com/sftp", "https://api.example.com/sftp/v1/sftp/auth/lookup"},
		{"https://api.example.com/sftp/", "https://api.example.com/sftp/v1/sftp/auth/lookup"},
		{"https://api.example.com/sftp?token=x", "https://api.example.com/sftp/v1/sftp/auth/lookup"},
	}
	for _, testCase := range cases {
		got, err := endpointURL(testCase.baseURL, "lookup")
		if err != nil {
			t.Fatalf("endpointURL(%q) error = %v", testCase.baseURL, err)
		}
		if got != testCase.want {
			t.Errorf("endpointURL(%q) = %q, want %q", testCase.baseURL, got, testCase.want)
		}
	}
}

// A client may change the user name between auth requests, so a policy cached
// for one name must not be reused for another.
func TestLookupIsNotReusedAcrossUsernames(t *testing.T) {
	var lookedUp []string
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/sftp/auth/lookup" {
			http.NotFound(writer, request)
			return
		}
		var received struct {
			Connection metadata `json:"connection"`
		}
		if err := json.NewDecoder(request.Body).Decode(&received); err != nil {
			t.Error(err)
			return
		}
		lookedUp = append(lookedUp, received.Connection.Username)
		_ = json.NewEncoder(writer).Encode(lookupResponse{Methods: []string{"password"}})
	}))
	defer backend.Close()

	authConn := New(config.Config{AuthBackend: &config.AuthBackend{BaseURL: backend.URL}}).NewConn(t.Context())
	fullBackend, ok := authConn.backend.(*fullAuth)
	if !ok {
		t.Fatalf("backend = %T, want *fullAuth", authConn.backend)
	}
	for _, username := range []string{"acme", "acme", "other", "other"} {
		if _, err := fullBackend.lookupPolicy(t.Context(), testConnection{username: username}); err != nil {
			t.Fatalf("lookupPolicy(%q) error = %v", username, err)
		}
	}
	if want := []string{"acme", "other"}; !slices.Equal(lookedUp, want) {
		t.Fatalf("lookups = %v, want %v", lookedUp, want)
	}
}

func TestBackendAuthenticationFailureIsTracedWithoutCredentials(t *testing.T) {
	recorder := tracetest.NewSpanRecorder()
	provider := trace.NewTracerProvider(trace.WithSpanProcessor(recorder))
	t.Cleanup(func() { _ = provider.Shutdown(t.Context()) })
	previousProvider := otel.GetTracerProvider()
	otel.SetTracerProvider(provider)
	t.Cleanup(func() { otel.SetTracerProvider(previousProvider) })
	tracer := provider.Tracer("test")

	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Error(writer, "backend details must not reach traces", http.StatusInternalServerError)
	}))
	defer backend.Close()

	connectionCtx, connectionSpan := tracer.Start(t.Context(), "ssh.connection")
	authConn := New(config.Config{AuthBackend: &config.AuthBackend{URL: backend.URL}}).NewConn(connectionCtx)
	if _, err := authConn.Password(testConnection{username: "acme"}, []byte("secret")); !errors.Is(err, errAuthFailed) {
		t.Fatalf("Password() error = %v, want errAuthFailed", err)
	}
	connectionSpan.End()

	spans := recorder.Ended()
	authentication := authSpanNamed(spans, "ssh.auth.password")
	request := authSpanNamed(spans, "HTTP POST")
	if authentication == nil || request == nil {
		t.Fatalf("ended spans = %v, want authentication and HTTP request", authSpanNames(spans))
	}
	if authentication.Parent().SpanID() != connectionSpan.SpanContext().SpanID() || request.Parent().SpanID() != authentication.SpanContext().SpanID() {
		t.Fatalf("unexpected span parentage: authentication=%s request=%s", authentication.Parent().SpanID(), request.Parent().SpanID())
	}
	if authentication.Status().Code != codes.Error || request.Status().Code != codes.Error {
		t.Fatalf("span status = authentication=%v request=%v, want error", authentication.Status(), request.Status())
	}
	if got := authSpanAttribute(request, "http.response.status_code"); got != "500" {
		t.Fatalf("backend HTTP status = %q, want 500", got)
	}
	for _, span := range []trace.ReadOnlySpan{authentication, request} {
		for _, value := range span.Attributes() {
			if string(value.Key) == "password" || value.Value.AsString() == "secret" || value.Value.AsString() == "backend details must not reach traces" {
				t.Fatalf("span %q exposes sensitive value %s=%q", span.Name(), value.Key, value.Value.AsString())
			}
		}
	}
}

func authSpanNamed(spans []trace.ReadOnlySpan, name string) trace.ReadOnlySpan {
	for _, span := range spans {
		if span.Name() == name {
			return span
		}
	}
	return nil
}

func authSpanNames(spans []trace.ReadOnlySpan) []string {
	names := make([]string, 0, len(spans))
	for _, span := range spans {
		names = append(names, span.Name())
	}
	return names
}

func authSpanAttribute(span trace.ReadOnlySpan, key string) string {
	for _, value := range span.Attributes() {
		if string(value.Key) == key {
			return value.Value.Emit()
		}
	}
	return ""
}

type testConnection struct{ username string }

func (c testConnection) User() string        { return c.username }
func (testConnection) SessionID() []byte     { return []byte("session-id") }
func (testConnection) ClientVersion() []byte { return []byte("SSH-2.0-client") }
func (testConnection) ServerVersion() []byte { return []byte("SSH-2.0-server") }
func (testConnection) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 49152}
}
func (testConnection) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 2222}
}
