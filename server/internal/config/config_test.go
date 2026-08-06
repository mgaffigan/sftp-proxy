package config

import (
	"os"
	"path/filepath"
	"testing"

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
}

func TestConfigValidateRejectsInvalidAllowedMethod(t *testing.T) {
	entry := Entry{Directory: "Inbound", Backend: "https://files.example.test/inbound", AllowedMethods: []string{"PUT"}}
	if err := entry.Validate(); err == nil {
		t.Fatal("Validate() succeeded with an unsupported allowed method")
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
