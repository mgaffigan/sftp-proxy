package auth

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"sftp-proxy/internal/config"
)

func TestPasswordAuthenticationFinalizesBackendSession(t *testing.T) {
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
			writer.WriteHeader(http.StatusNoContent)
		case "/v1/sftp/auth/finalize":
			if _, err := request.Cookie("session"); err != nil {
				t.Fatalf("finalize request did not retain cookie: %v", err)
			}
			_ = json.NewEncoder(writer).Encode(finalizeResponse{User: config.User{RootFS: config.RootFS{Children: []config.Entry{{
				Directory: "Inbound",
				Backend:   "https://files.example.test/inbound",
			}}}}})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer backend.Close()

	authConn := New(config.Config{AuthBackend: &config.AuthBackend{BaseURL: backend.URL}}).NewConn()
	permissions, err := authConn.Password(testConnection{username: "acme"}, []byte("not logged"))
	if err != nil {
		t.Fatalf("Password() error = %v", err)
	}
	session, found := SessionFrom(permissions)
	if !found || session.User.Username != "acme" || len(session.User.RootFS.Children) != 1 {
		t.Fatalf("unexpected session: %#v, found=%v", session, found)
	}
	if len(calls) != 3 {
		t.Fatalf("backend calls = %v, want lookup, password, finalize", calls)
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
			Method     string   `json:"method"`
		}
		if err := json.NewDecoder(httpRequest.Body).Decode(&received); err != nil {
			t.Fatal(err)
		}
		if received.Connection.Username != "acme" || received.Password != "secret" || received.Method != "password" {
			t.Fatalf("unexpected auth request: %#v", received)
		}
		_ = json.NewEncoder(writer).Encode(finalizeResponse{User: config.User{RootFS: config.RootFS{Children: []config.Entry{{
			Directory: "Inbound",
			Backend:   backend.URL + "/upload",
		}}}}})
	}))
	defer backend.Close()

	authConn := New(config.Config{AuthBackend: &config.AuthBackend{URL: backend.URL + "/auth"}}).NewConn()
	permissions, err := authConn.Password(testConnection{username: "acme"}, []byte("secret"))
	if err != nil {
		t.Fatalf("Password() error = %v", err)
	}
	if session, found := SessionFrom(permissions); !found || session.User.Username != "acme" {
		t.Fatalf("unexpected session: %#v, found=%v", session, found)
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

	authConn := New(config.Config{AuthBackend: &config.AuthBackend{BaseURL: backend.URL}}).NewConn()
	for _, username := range []string{"acme", "acme", "other", "other"} {
		if _, err := authConn.lookupPolicy(testConnection{username: username}); err != nil {
			t.Fatalf("lookupPolicy(%q) error = %v", username, err)
		}
	}
	if want := []string{"acme", "other"}; !slices.Equal(lookedUp, want) {
		t.Fatalf("lookups = %v, want %v", lookedUp, want)
	}
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
