package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestConfigValidateAcceptsStaticHTTPUser(t *testing.T) {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("correct horse battery staple"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		HostKeyFile:      "host_key",
		Port:             2222,
		UploadStagingDir: "staging",
		Users: []User{{
			Username:     "acme",
			PasswordHash: string(passwordHash),
			RootFS: RootFS{Children: []Entry{{
				Directory:      "Inbound",
				Backend:        "https://files.example.test/inbound",
				AllowedMethods: []string{"POST"},
			}}},
		}},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	cfg.Users[0].MaxConcurrentUploads = -1
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() accepted a negative maxConcurrentUploads")
	}
}

func TestRootFSValidatesItsOwnBackendAndMethods(t *testing.T) {
	root := RootFS{Backend: "https://files.example.test/root", AllowedMethods: []string{"GET", "POST"}}
	if err := root.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if err := (RootFS{Backend: "ftp://files.example.test"}).Validate(); err == nil {
		t.Fatal("Validate() accepted a non-HTTP root backend")
	}
	if err := (RootFS{Backend: "https://files.example.test", AllowedMethods: []string{"PUT"}}).Validate(); err == nil {
		t.Fatal("Validate() accepted an unsupported root method")
	}
	// A root with neither backend nor children is an empty filesystem, not an
	// error, and is what an empty backend listing validates as.
	if err := (RootFS{}).Validate(); err != nil {
		t.Fatalf("Validate() on an empty root error = %v", err)
	}
}

func TestConfigValidateRejectsAllowedMethodsWithoutABackend(t *testing.T) {
	// The list constrains requests to a backend, so it is meaningless on a
	// statically served directory and is refused rather than ignored.
	entry := Entry{
		Directory:      "Static",
		Children:       []Entry{{File: "a.txt", Backend: "https://files.example.test/a.txt"}},
		AllowedMethods: []string{"GET"},
	}
	if err := entry.Validate(); err == nil {
		t.Fatal("Validate() accepted allowedMethods on an entry with no backend")
	}
	if err := (RootFS{AllowedMethods: []string{"GET"}}).Validate(); err == nil {
		t.Fatal("Validate() accepted allowedMethods on a root with no backend")
	}
}

func TestConfigValidateRejectsInvalidAllowedMethod(t *testing.T) {
	entry := Entry{Directory: "Inbound", Backend: "https://files.example.test/inbound", AllowedMethods: []string{"PUT"}}
	if err := entry.Validate(); err == nil {
		t.Fatal("Validate() succeeded with an unsupported allowed method")
	}
}

func TestConfigValidateAcceptsDirectoryUploadSizeLimit(t *testing.T) {
	entry := Entry{Directory: "Inbound", Backend: "https://files.example.test/inbound", MaxUploadSize: 1}
	if err := entry.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestEntryValidatesPermissionBits(t *testing.T) {
	permissions := uint32(0640)
	entry := Entry{File: "report.txt", Backend: "https://files.example.test/report.txt", Permissions: &permissions}
	if err := entry.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	permissions = 01000
	if err := entry.Validate(); err == nil {
		t.Fatal("Validate() accepted non-permission mode bits")
	}
}

func TestConfigValidateRejectsTraversalEntry(t *testing.T) {
	cfg := Config{
		HostKeyFile:      "host_key",
		Port:             2222,
		UploadStagingDir: "staging",
		AuthBackend:      &AuthBackend{BaseURL: "https://auth.example.test"},
		Users: []User{{
			Username:     "acme",
			PasswordHash: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
			RootFS: RootFS{Children: []Entry{{
				Directory: "..",
				Backend:   "https://files.example.test/inbound",
			}}},
		}},
	}

	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() succeeded for traversal entry")
	}
}

func TestConfigValidateRejectsUnconfiguredAuthentication(t *testing.T) {
	cfg := Config{
		HostKeyFile:      "host_key",
		Port:             2222,
		UploadStagingDir: "staging",
	}

	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() succeeded without users or auth backend")
	}
}

func TestAuthBackendValidateAcceptsSingleEndpoint(t *testing.T) {
	backend := AuthBackend{URL: "http://localhost:8080/auth"}
	if err := backend.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestAuthBackendValidateRejectsAmbiguousEndpoint(t *testing.T) {
	backend := AuthBackend{BaseURL: "http://localhost:8080", URL: "http://localhost:8080/auth"}
	if err := backend.Validate(); err == nil {
		t.Fatal("Validate() succeeded with both baseURL and url")
	}
}

func TestLoadRejectsMultipleJSONValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{} {}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load() accepted multiple JSON values")
	}
}

func TestLoadAcceptsSchemaDeclaration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	contents := `{
  "$schema": "https://example.test/sftp-proxy.schema.json",
  "hostKeyFile": "host_key",
  "authBackend": {"url": "http://localhost:8080/auth"}
}`
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}

	config, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if config.Schema != "https://example.test/sftp-proxy.schema.json" {
		t.Fatalf("Schema = %q", config.Schema)
	}
}

// An omitted timeout takes its default; an explicit 0 means "no limit", which
// is the OpenSSH meaning and must not be confused with the omitted case.
func TestTimeoutDefaultsDistinguishOmittedFromZero(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	contents := `{
  "hostKeyFile": "host_key",
  "loginGraceMs": 0,
  "authBackend": {"url": "http://localhost:8080/auth", "timeoutMs": 5}
}`
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}

	config, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got := config.LoginGrace(); got != 0 {
		t.Errorf("LoginGrace() = %v, want 0 (no limit)", got)
	}
	if got := config.AuthBackend.RequestTimeout(); got != 5*time.Millisecond {
		t.Errorf("RequestTimeout() = %v, want 5ms", got)
	}

	var omitted Config
	if got := omitted.LoginGrace(); got != DefaultLoginGrace {
		t.Errorf("LoginGrace() = %v, want %v", got, DefaultLoginGrace)
	}
	if got := omitted.AuthBackend.RequestTimeout(); got != DefaultAuthBackendTimeout {
		t.Errorf("RequestTimeout() on nil backend = %v, want %v", got, DefaultAuthBackendTimeout)
	}
}

func TestClientAliveDefaultsAndClamping(t *testing.T) {
	never := 0
	negative := -1
	cases := []struct {
		name         string
		user         User
		wantInterval time.Duration
		wantCountMax int
	}{
		{"omitted disables probing", User{}, 0, DefaultClientAliveCountMax},
		{"interval only takes default count", User{ClientAliveMs: 30}, 30 * time.Millisecond, DefaultClientAliveCountMax},
		{"explicit zero count never terminates", User{ClientAliveMs: 30, ClientAliveCountMax: &never}, 30 * time.Millisecond, 0},
		{"negatives from a backend are clamped", User{ClientAliveMs: -5, ClientAliveCountMax: &negative}, 0, 0},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			interval, countMax := testCase.user.ClientAlive()
			if interval != testCase.wantInterval || countMax != testCase.wantCountMax {
				t.Fatalf("ClientAlive() = %v, %d, want %v, %d", interval, countMax, testCase.wantInterval, testCase.wantCountMax)
			}
		})
	}
}
