package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

// localUser is a configuration whose one directory is served from a local path,
// which is what fileBackend has to consent to.
func localUser(backend string, fileBackend *FileBackend) Config {
	return Config{
		HostKeyFile:      "host_key",
		Port:             2222,
		UploadStagingDir: "staging",
		FileBackend:      fileBackend,
		Users: []User{{
			Username:     "acme",
			PasswordHash: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
			RootFS:       RootFS{Children: []Entry{{Directory: "Inbound", Backend: backend}}},
		}},
	}
}

func TestConfigValidateAcceptsALocalPathTheDeploymentAllowed(t *testing.T) {
	cfg := localUser("file:///srv/sftp/acme/inbound", &FileBackend{AllowedPrefixes: []string{"/srv/sftp/acme"}})
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	// The prefix itself, and the host RFC 8089 lets a file URL name, are the
	// same consent.
	cfg = localUser("file://localhost/srv/sftp/acme", &FileBackend{AllowedPrefixes: []string{"/srv/sftp/acme"}})
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestConfigValidateRejectsALocalPathTheDeploymentDidNot(t *testing.T) {
	// Withheld entirely: with no fileBackend there is no local path to serve.
	if err := localUser("file:///srv/sftp/acme", nil).Validate(); err == nil {
		t.Fatal("Validate() served a local path with no fileBackend")
	}

	// Allowed elsewhere. A sibling whose name merely starts with the prefix is
	// a different directory.
	for _, backend := range []string{
		"file:///etc",
		"file:///srv/sftp/acmeX/inbound",
		"file:///srv/sftp",
	} {
		cfg := localUser(backend, &FileBackend{AllowedPrefixes: []string{"/srv/sftp/acme"}})
		if err := cfg.Validate(); err == nil {
			t.Errorf("Validate() served %q", backend)
		}
	}
}

func TestConfigValidateChecksLocalPathsThroughoutTheTree(t *testing.T) {
	cfg := localUser("https://files.example.test/inbound", &FileBackend{AllowedPrefixes: []string{"/srv/sftp/acme"}})
	cfg.Users[0].RootFS.Children[0].Children = []Entry{{
		Directory: "Archive",
		Children:  []Entry{{File: "old.txt", Backend: "file:///etc/shadow"}},
	}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() served a local path nested in the tree")
	}

	// A root served locally answers to the same consent as any other node.
	cfg = localUser("https://files.example.test/inbound", nil)
	cfg.Users[0].RootFS.Backend = "file:///srv/sftp/acme"
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() served a local root with no fileBackend")
	}
}

func TestFileBackendValidate(t *testing.T) {
	for name, prefixes := range map[string][]string{
		"none":      {},
		"relative":  {"srv/sftp"},
		"unclean":   {"/srv/sftp/"},
		"traversal": {"/srv/sftp/../data"},
		"duplicate": {"/srv/sftp", "/srv/sftp"},
		"nested":    {"/srv/sftp", "/srv/sftp/acme"},
		"parent":    {"/srv/sftp/acme", "/srv"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := (FileBackend{AllowedPrefixes: prefixes}).Validate(); err == nil {
				t.Fatalf("Validate(%v) accepted it", prefixes)
			}
		})
	}

	allowed := FileBackend{AllowedPrefixes: []string{"/srv/sftp/acme", "/var/spool/outbound"}}
	if err := allowed.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestLocalPathAcceptsOnlyAPlainLocalPath(t *testing.T) {
	for _, rawURL := range []string{"file:///srv/sftp", "file://localhost/srv/sftp", "file:///srv/sftp/../sftp"} {
		if path, ok := LocalPath(rawURL); !ok || path != "/srv/sftp" {
			t.Errorf("LocalPath(%q) = (%q, %v), want /srv/sftp", rawURL, path, ok)
		}
	}
	if path, ok := LocalPath("file:///srv/an%20odd%20name.txt"); !ok || path != "/srv/an odd name.txt" {
		t.Errorf("LocalPath() = (%q, %v), want the decoded name", path, ok)
	}

	for _, rawURL := range []string{
		"https://files.example.test/d",
		"file://elsewhere/srv/sftp",
		"file:///srv/sftp?renameTo=%2Fx",
		"file:///srv/sftp#fragment",
		"file://user@localhost/srv/sftp",
		"file:relative/path",
		"file://",
	} {
		if path, ok := LocalPath(rawURL); ok {
			t.Errorf("LocalPath(%q) = %q, want it refused", rawURL, path)
		}
	}
}

func TestConfigValidateRejectsAllowedMethodsOnALocalEntry(t *testing.T) {
	cfg := localUser("file:///srv/sftp/acme", &FileBackend{AllowedPrefixes: []string{"/srv/sftp/acme"}})
	cfg.Users[0].RootFS.Children[0].AllowedMethods = []string{"POST"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() accepted allowedMethods on a local entry")
	}
}

func s3User(backend string, access *S3Access, s3Backend *S3Backend) Config {
	return Config{
		HostKeyFile:      "host_key",
		Port:             2222,
		UploadStagingDir: "staging",
		S3Backend:        s3Backend,
		Users: []User{{
			Username:     "acme",
			PasswordHash: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
			RootFS:       RootFS{Children: []Entry{{Directory: "Archive", Backend: backend, S3: access}}},
		}},
	}
}

func configuredBucket(name string) *S3Backend {
	return &S3Backend{Buckets: []S3Bucket{{
		Bucket:   name,
		S3Access: S3Access{Region: "us-east-1", AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI"},
	}}}
}

func statedAccess() *S3Access {
	return &S3Access{Region: "us-east-1", AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI"}
}

func TestS3LocationAcceptsOnlyABucketAndAKey(t *testing.T) {
	for rawURL, want := range map[string][2]string{
		"s3://acme-archive":                 {"acme-archive", ""},
		"s3://acme-archive/":                {"acme-archive", ""},
		"s3://acme-archive/2026":            {"acme-archive", "2026"},
		"s3://acme-archive/2026/q1":         {"acme-archive", "2026/q1"},
		"s3://acme-archive/an%20odd%20name": {"acme-archive", "an odd name"},
	} {
		bucket, key, ok := S3Location(rawURL)
		if !ok || bucket != want[0] || key != want[1] {
			t.Errorf("S3Location(%q) = (%q, %q, %v), want (%q, %q, true)", rawURL, bucket, key, ok, want[0], want[1])
		}
	}

	for _, rawURL := range []string{
		"https://files.example.test/d",
		"s3://acme-archive/2026?renameTo=%2Fx",
		"s3://acme-archive/2026#fragment",
		"s3://user@acme-archive/2026",
		"s3://acme-archive/2026/../secret",
		"s3://acme-archive/2026/./here",
		"s3://ACME/2026",
		"s3://ab/2026",
		"s3://192.168.0.1/2026",
		"s3://-acme/2026",
		"s3://acme-/2026",
		"s3://acme..archive/2026",
		"s3:relative/path",
		"s3://",
	} {
		if bucket, key, ok := S3Location(rawURL); ok {
			t.Errorf("S3Location(%q) = (%q, %q), want it refused", rawURL, bucket, key)
		}
	}
}

func TestConfigValidateAcceptsAConfiguredBucket(t *testing.T) {
	cfg := s3User("s3://acme-archive/2026", nil, configuredBucket("acme-archive"))
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

// A bucket table is not the only authority: an entry stating its own
// credentials names a bucket the deployment never heard of, which is what lets
// one proxy serve tenants it cannot enumerate.
func TestConfigValidateAcceptsAnEntryStatingItsOwnCredentials(t *testing.T) {
	cfg := s3User("s3://tenant-42-archive/2026", statedAccess(), &S3Backend{})
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestConfigValidateRejectsAnUnreachableBucket(t *testing.T) {
	cfg := s3User("s3://other-bucket/2026", nil, configuredBucket("acme-archive"))
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() accepted a bucket with neither configured nor stated credentials")
	}
}

// The s3 scheme is withheld by leaving s3Backend out, as the file scheme is by
// leaving fileBackend out.
func TestConfigValidateRejectsAnS3URLWithoutTheBackend(t *testing.T) {
	cfg := s3User("s3://acme-archive/2026", statedAccess(), nil)
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() accepted an s3 backend URL with no s3Backend")
	}
}

func TestConfigValidateRejectsCredentialsWithoutAnS3Backend(t *testing.T) {
	cfg := s3User("https://files.example.test/archive", statedAccess(), &S3Backend{})
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() accepted s3 credentials on an HTTP entry")
	}
}

func TestConfigValidateRejectsIncompleteStatedCredentials(t *testing.T) {
	access := statedAccess()
	access.SecretAccessKey = ""
	cfg := s3User("s3://acme-archive/2026", access, &S3Backend{})
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() accepted an access key without its secret")
	}

	access = statedAccess()
	access.Region = ""
	cfg = s3User("s3://acme-archive/2026", access, &S3Backend{})
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() accepted stated credentials with no region")
	}
}

func TestConfigValidateRejectsAllowedMethodsOnAnS3Entry(t *testing.T) {
	cfg := s3User("s3://acme-archive/2026", nil, configuredBucket("acme-archive"))
	cfg.Users[0].RootFS.Children[0].AllowedMethods = []string{"GET"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() accepted allowedMethods on an s3 entry")
	}
}

// Ambient credentials are the proxy's own identity. Only the configuration file
// can ask for them, and S3Access — all a backend may send — cannot express it.
func TestS3BucketValidateGovernsAmbientCredentials(t *testing.T) {
	ambient := S3Backend{Buckets: []S3Bucket{{Bucket: "acme-archive", UseDefaultCredentials: true,
		S3Access: S3Access{Region: "us-east-1"}}}}
	if err := ambient.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	both := S3Backend{Buckets: []S3Bucket{{Bucket: "acme-archive", UseDefaultCredentials: true,
		S3Access: S3Access{Region: "us-east-1", AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI"}}}}
	if err := both.Validate(); err == nil {
		t.Fatal("Validate() accepted an ambient bucket that also states a key")
	}

	duplicate := S3Backend{Buckets: []S3Bucket{
		{Bucket: "acme-archive", S3Access: *statedAccess()},
		{Bucket: "acme-archive", S3Access: *statedAccess()},
	}}
	if err := duplicate.Validate(); err == nil {
		t.Fatal("Validate() accepted the same bucket twice")
	}
}

func TestS3BucketValidateChecksTheEndpoint(t *testing.T) {
	for _, endpoint := range []string{"ftp://minio:9000", "minio:9000", "https://user:pass@minio:9000", "https://minio:9000?x=1"} {
		bucket := S3Bucket{Bucket: "acme-archive", S3Access: *statedAccess()}
		bucket.Endpoint = endpoint
		if err := bucket.Validate(); err == nil {
			t.Errorf("Validate() accepted endpoint %q", endpoint)
		}
	}
	bucket := S3Bucket{Bucket: "acme-archive", S3Access: *statedAccess()}
	bucket.Endpoint = "http://minio:9000"
	if err := bucket.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

// A fixed endpoint is addressed path-style unless it says otherwise; AWS, which
// has no endpoint stated, is not.
func TestUsePathStyleFollowsTheEndpoint(t *testing.T) {
	if (S3Access{}).UsePathStyle() {
		t.Error("UsePathStyle() = true for AWS, want false")
	}
	if !(S3Access{Endpoint: "http://minio:9000"}).UsePathStyle() {
		t.Error("UsePathStyle() = false for a stated endpoint, want true")
	}
	virtual := false
	if (S3Access{Endpoint: "http://minio:9000", PathStyle: &virtual}).UsePathStyle() {
		t.Error("UsePathStyle() = true, want the stated false")
	}
}

// Nothing logs an access today. This is so that a line added later cannot.
func TestS3AccessLogsNoSecret(t *testing.T) {
	logged := statedAccess().LogValue().String()
	for _, secret := range []string{"AKIAEXAMPLE", "wJalrXUtnFEMI"} {
		if strings.Contains(logged, secret) {
			t.Errorf("LogValue() = %q, which names %q", logged, secret)
		}
	}
}

// A backend directory listing uses the entry shape, decoded with unknown fields
// refused. This is what an HTTP backend sends to hand over a tenant's bucket.
func TestAnEntryDecodesStatedCredentials(t *testing.T) {
	listing := `{"children":[{"directory":"Archive","backend":"s3://tenant-42-archive/2026",
		"permissions":365,"s3":{"region":"us-east-1","endpoint":"http://minio:9000",
		"accessKeyId":"AKIAEXAMPLE","secretAccessKey":"wJalrXUtnFEMI","sessionToken":"IQoJ"}}]}`

	var decoded struct {
		Children []Entry `json:"children"`
	}
	decoder := json.NewDecoder(strings.NewReader(listing))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if err := ValidateEntries(decoded.Children); err != nil {
		t.Fatalf("ValidateEntries() error = %v", err)
	}
	access := decoded.Children[0].S3
	if access == nil || access.AccessKeyID != "AKIAEXAMPLE" || access.SessionToken != "IQoJ" {
		t.Fatalf("s3 = %+v, want the stated credentials", access)
	}
	if !access.UsePathStyle() {
		t.Error("UsePathStyle() = false for a stated endpoint, want true")
	}
}

// A configured bucket is one flat object, so the table stays readable.
func TestAnS3BucketDecodesAsOneObject(t *testing.T) {
	var bucket S3Bucket
	decoder := json.NewDecoder(strings.NewReader(
		`{"bucket":"acme-archive","region":"us-east-1","useDefaultCredentials":true}`))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&bucket); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if bucket.Bucket != "acme-archive" || bucket.Region != "us-east-1" || !bucket.UseDefaultCredentials {
		t.Fatalf("decoded %+v, want the stated bucket", bucket)
	}
}
