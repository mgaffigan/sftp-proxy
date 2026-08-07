package httpfs

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/pkg/sftp"

	"sftp-proxy/internal/config"
)

func TestFilesystemListsDirectoryAndReadsRanges(t *testing.T) {
	var rangeHeader string
	var backend *httptest.Server
	backend = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/outbound":
			writer.Header().Set("Content-Type", directoryContentType)
			_, _ = writer.Write([]byte(`{"children":[{"file":"report.txt","size":4,"backend":"` + backend.URL + `/outbound/report.txt"}]}`))
		case "/outbound/report.txt":
			rangeHeader = request.Header.Get("Range")
			writer.WriteHeader(http.StatusPartialContent)
			_, _ = writer.Write([]byte("port"))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer backend.Close()

	filesystem := New(config.RootFS{Children: []config.Entry{{Directory: "Outbound", Backend: backend.URL + "/outbound"}}}, t.TempDir(), backend.Client())
	lister, err := filesystem.Filelist(sftp.NewRequest("List", "/Outbound"))
	if err != nil {
		t.Fatalf("Filelist() error = %v", err)
	}
	entries := make([]os.FileInfo, 1)
	if count, err := lister.ListAt(entries, 0); count != 1 || err != nil {
		t.Fatalf("ListAt() = (%d, %v), want (1, nil)", count, err)
	}
	if entries[0].Name() != "report.txt" {
		t.Fatalf("entry name = %q, want report.txt", entries[0].Name())
	}
	if entries[0].Size() != 4 {
		t.Fatalf("entry size = %d, want 4", entries[0].Size())
	}

	reader, err := filesystem.Fileread(sftp.NewRequest("Get", "/Outbound/report.txt"))
	if err != nil {
		t.Fatalf("Fileread() error = %v", err)
	}
	data := make([]byte, 4)
	if count, err := reader.ReadAt(data, 12); count != 4 || err != nil {
		t.Fatalf("ReadAt() = (%d, %v), want (4, nil)", count, err)
	}
	if string(data) != "port" {
		t.Fatalf("read data = %q, want port", data)
	}
	if rangeHeader != "bytes=12-15" {
		t.Fatalf("Range header = %q, want bytes=12-15", rangeHeader)
	}
}

func TestFilesystemStagesAndPostsUpload(t *testing.T) {
	var method, contentType, body string
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/inbound" && request.Method == http.MethodGet {
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		method = request.Method
		contentType = request.Header.Get("Content-Type")
		contents, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		body = string(contents)
		writer.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	filesystem := New(config.RootFS{Children: []config.Entry{{Directory: "Inbound", Backend: backend.URL + "/inbound"}}}, t.TempDir(), backend.Client())
	request := sftp.NewRequest("Put", "/Inbound/new.txt").WithContext(context.Background())
	writer, err := filesystem.Filewrite(request)
	if err != nil {
		t.Fatalf("Filewrite() error = %v", err)
	}
	if _, err := writer.WriteAt([]byte("hello"), 0); err != nil {
		t.Fatalf("WriteAt() error = %v", err)
	}
	if err := writer.(io.Closer).Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if method != http.MethodPost || contentType != "application/octet-stream" || body != "hello" {
		t.Fatalf("upload = (%s, %s, %q)", method, contentType, body)
	}
}

func TestFilesystemFiltersDisallowedDirectoryMethods(t *testing.T) {
	requests := 0
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if request.Method != http.MethodPost || request.URL.Path != "/inbound/new.txt" {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		writer.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	filesystem := New(config.RootFS{Children: []config.Entry{{
		Directory:      "Inbound",
		Backend:        backend.URL + "/inbound",
		AllowedMethods: []string{http.MethodPost},
	}}}, t.TempDir(), backend.Client())
	lister, err := filesystem.Filelist(sftp.NewRequest("List", "/Inbound"))
	if err != nil {
		t.Fatalf("Filelist() error = %v", err)
	}
	entries := make([]os.FileInfo, 1)
	if count, err := lister.ListAt(entries, 0); count != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("ListAt() = (%d, %v), want (0, EOF)", count, err)
	}
	if requests != 0 {
		t.Fatalf("backend requests = %d, want 0", requests)
	}

	writer, err := filesystem.Filewrite(sftp.NewRequest("Put", "/Inbound/new.txt"))
	if err != nil {
		t.Fatalf("Filewrite() error = %v", err)
	}
	if err := writer.(io.Closer).Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if requests != 1 {
		t.Fatalf("backend requests = %d, want 1", requests)
	}
}

func TestFilesystemMapsNotFoundToSFTPError(t *testing.T) {
	backend := httptest.NewServer(http.NotFoundHandler())
	defer backend.Close()

	filesystem := New(config.RootFS{Children: []config.Entry{{File: "missing.txt", Backend: backend.URL + "/missing.txt"}}}, t.TempDir(), backend.Client())
	reader, err := filesystem.Fileread(sftp.NewRequest("Get", "/missing.txt"))
	if err != nil {
		t.Fatalf("Fileread() error = %v", err)
	}
	_, err = reader.ReadAt(make([]byte, 1), 0)
	if !errors.Is(err, sftp.ErrSSHFxNoSuchFile) {
		t.Fatalf("ReadAt() error = %v, want no such file", err)
	}
}

// deletions records every DELETE the backend receives, and serves a tree in
// which each entry's allowed_methods disagree with its directory's, so that any
// inheritance would show up as a wrong answer.
func mixedMethodsBackend(t *testing.T, deletions *[]string) (*httptest.Server, *Filesystem) {
	t.Helper()
	var backend *httptest.Server
	backend = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodDelete {
			*deletions = append(*deletions, request.URL.RequestURI())
			writer.WriteHeader(http.StatusOK)
			return
		}
		writer.Header().Set("Content-Type", directoryContentType)
		switch request.URL.Path {
		case "/files":
			_, _ = writer.Write([]byte(`{"children":[
				{"directory":"readonly","backend":"` + backend.URL + `/files/readonly","allowed_methods":["GET"]},
				{"directory":"writable","backend":"` + backend.URL + `/files/writable","allowed_methods":["GET","POST","DELETE"]}
			]}`))
		case "/files/readonly":
			_, _ = writer.Write([]byte(`{"children":[
				{"file":"mutable.txt","backend":"` + backend.URL + `/files/readonly/mutable.txt","allowed_methods":["GET","POST","DELETE"]},
				{"file":"frozen.txt","backend":"` + backend.URL + `/files/readonly/frozen.txt","allowed_methods":["GET"]}
			]}`))
		case "/files/writable":
			_, _ = writer.Write([]byte(`{"children":[
				{"file":"frozen.txt","backend":"` + backend.URL + `/files/writable/frozen.txt","allowed_methods":["GET"]}
			]}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	filesystem := New(config.RootFS{Children: []config.Entry{{
		Directory: "Files",
		Backend:   backend.URL + "/files",
	}}}, t.TempDir(), backend.Client())
	return backend, filesystem
}

func TestFilesystemRootWithBackendListsUploadsAndResolves(t *testing.T) {
	var uploaded string
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.URL.Path == "/root" && request.Method == http.MethodGet:
			writer.Header().Set("Content-Type", directoryContentType)
			_, _ = writer.Write([]byte(`{"children":[{"file":"existing.txt","size":2,"backend":"http://` + request.Host + `/root/existing.txt"}]}`))
		case request.URL.Path == "/root/new.txt" && request.Method == http.MethodPost:
			contents, err := io.ReadAll(request.Body)
			if err != nil {
				t.Error(err)
			}
			uploaded = string(contents)
			writer.WriteHeader(http.StatusOK)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer backend.Close()

	filesystem := New(config.RootFS{Backend: backend.URL + "/root"}, t.TempDir(), backend.Client())

	// The root lists from its backend, with no statically configured children.
	lister, err := filesystem.Filelist(sftp.NewRequest("List", "/"))
	if err != nil {
		t.Fatalf("Filelist(/) error = %v", err)
	}
	entries := make([]os.FileInfo, 1)
	if count, err := lister.ListAt(entries, 0); count != 1 || err != nil {
		t.Fatalf("ListAt() = (%d, %v), want (1, nil)", count, err)
	}
	if entries[0].Name() != "existing.txt" {
		t.Fatalf("entry name = %q, want existing.txt", entries[0].Name())
	}

	// A child of the backend-listed root resolves like any other child.
	if _, err := filesystem.Filelist(sftp.NewRequest("Stat", "/existing.txt")); err != nil {
		t.Fatalf("Filelist(Stat) error = %v", err)
	}

	// Uploading into the root POSTs to the root backend's URL.
	writer, err := filesystem.Filewrite(sftp.NewRequest("Put", "/new.txt").WithContext(context.Background()))
	if err != nil {
		t.Fatalf("Filewrite(/new.txt) error = %v", err)
	}
	if _, err := writer.WriteAt([]byte("hi"), 0); err != nil {
		t.Fatalf("WriteAt() error = %v", err)
	}
	if err := writer.(io.Closer).Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if uploaded != "hi" {
		t.Fatalf("uploaded = %q, want hi", uploaded)
	}
}

func TestFilesystemRootMethodsApplyToTheRoot(t *testing.T) {
	requests := 0
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if request.Method != http.MethodPost || request.URL.Path != "/root/drop.txt" {
			t.Errorf("request = %s %s", request.Method, request.URL.Path)
		}
		writer.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	// A drop-only root: POST but no GET, exactly as for a drop-only directory.
	filesystem := New(config.RootFS{
		Backend:        backend.URL + "/root",
		AllowedMethods: []string{http.MethodPost},
	}, t.TempDir(), backend.Client())

	lister, err := filesystem.Filelist(sftp.NewRequest("List", "/"))
	if err != nil {
		t.Fatalf("Filelist(/) error = %v", err)
	}
	if count, err := lister.ListAt(make([]os.FileInfo, 1), 0); count != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("ListAt() = (%d, %v), want (0, EOF)", count, err)
	}
	if requests != 0 {
		t.Fatalf("backend requests = %d, want the listing to be refused locally", requests)
	}

	writer, err := filesystem.Filewrite(sftp.NewRequest("Put", "/drop.txt"))
	if err != nil {
		t.Fatalf("Filewrite() error = %v", err)
	}
	if err := writer.(io.Closer).Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if requests != 1 {
		t.Fatalf("backend requests = %d, want 1", requests)
	}
}

func TestFilesystemAllowedMethodsAreNotInherited(t *testing.T) {
	var deletions []string
	backend, filesystem := mixedMethodsBackend(t, &deletions)
	defer backend.Close()

	// A mutable file inside a read-only directory is deletable: the file's own
	// methods decide, and the directory's GET-only list is about the directory.
	if err := filesystem.Filecmd(sftp.NewRequest("Remove", "/Files/readonly/mutable.txt")); err != nil {
		t.Fatalf("Filecmd(Remove mutable) error = %v", err)
	}
	if len(deletions) != 1 || deletions[0] != "/files/readonly/mutable.txt" {
		t.Fatalf("deletions = %v, want [/files/readonly/mutable.txt]", deletions)
	}

	// An immutable file inside a writable directory is not deletable, for the
	// same reason read the other way round.
	err := filesystem.Filecmd(sftp.NewRequest("Remove", "/Files/writable/frozen.txt"))
	if !errors.Is(err, sftp.ErrSSHFxOpUnsupported) {
		t.Fatalf("Filecmd(Remove frozen) error = %v, want op unsupported", err)
	}
	if len(deletions) != 1 {
		t.Fatalf("deletions = %v, want the refused delete to reach no backend", deletions)
	}
}

func TestFilesystemRenameConsultsOnlyTheSource(t *testing.T) {
	var deletions []string
	backend, filesystem := mixedMethodsBackend(t, &deletions)
	defer backend.Close()

	// Rename is one DELETE on the source, so the source's DELETE is the whole
	// decision — the destination directory allowing only GET is irrelevant.
	request := sftp.NewRequest("Rename", "/Files/readonly/mutable.txt")
	request.Target = "/Files/readonly/renamed.txt"
	if err := filesystem.Filecmd(request); err != nil {
		t.Fatalf("Filecmd(Rename) error = %v", err)
	}
	want := "/files/readonly/mutable.txt?renameTo=%2FFiles%2Freadonly%2Frenamed.txt"
	if len(deletions) != 1 || deletions[0] != want {
		t.Fatalf("deletions = %v, want [%s]", deletions, want)
	}

	// A source without DELETE cannot be renamed.
	request = sftp.NewRequest("Rename", "/Files/readonly/frozen.txt")
	request.Target = "/Files/readonly/thawed.txt"
	if err := filesystem.Filecmd(request); !errors.Is(err, sftp.ErrSSHFxOpUnsupported) {
		t.Fatalf("Filecmd(Rename frozen) error = %v, want op unsupported", err)
	}
	if len(deletions) != 1 {
		t.Fatalf("deletions = %v, want the refused rename to reach no backend", deletions)
	}
}

func TestFilesystemRenamePassesUnresolvableTargetsToTheBackend(t *testing.T) {
	var deletions []string
	backend, filesystem := mixedMethodsBackend(t, &deletions)
	defer backend.Close()

	// The destination need not resolve, or even exist: the source backend
	// decides what renameTo it will accept.
	request := sftp.NewRequest("Rename", "/Files/readonly/mutable.txt")
	request.Target = "/Nowhere/at/all.txt"
	if err := filesystem.Filecmd(request); err != nil {
		t.Fatalf("Filecmd(Rename) error = %v", err)
	}
	want := "/files/readonly/mutable.txt?renameTo=%2FNowhere%2Fat%2Fall.txt"
	if len(deletions) != 1 || deletions[0] != want {
		t.Fatalf("deletions = %v, want [%s]", deletions, want)
	}

	// A malformed destination is still refused, since renameTo must be a
	// well-formed root-relative path.
	for _, target := range []string{"", "relative.txt", "/Files/../escape.txt", "/"} {
		request = sftp.NewRequest("Rename", "/Files/readonly/mutable.txt")
		request.Target = target
		if err := filesystem.Filecmd(request); !errors.Is(err, sftp.ErrSSHFxNoSuchFile) {
			t.Fatalf("Filecmd(Rename to %q) error = %v, want no such file", target, err)
		}
	}
	if len(deletions) != 1 {
		t.Fatalf("deletions = %v, want the refused renames to reach no backend", deletions)
	}
}

func TestRangeReaderReturnsEOFForShortFinalRange(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Range") != "bytes=0-7" {
			t.Fatalf("Range = %q", request.Header.Get("Range"))
		}
		writer.WriteHeader(http.StatusPartialContent)
		_, _ = writer.Write([]byte("last"))
	}))
	defer backend.Close()

	reader := &rangeReader{ctx: context.Background(), fs: New(config.RootFS{}, t.TempDir(), backend.Client()), backendURL: backend.URL}
	buffer := make([]byte, 8)
	count, err := reader.ReadAt(buffer, 0)
	if count != 4 || !errors.Is(err, io.EOF) {
		t.Fatalf("ReadAt() = (%d, %v), want (4, EOF)", count, err)
	}
}

func TestRangeReaderReturnsEOFForSpeculativeReadAfterEOF(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Range") != "bytes=32768-65535" {
			t.Fatalf("Range = %q", request.Header.Get("Range"))
		}
		writer.Header().Set("Content-Range", "bytes */10")
		writer.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
	}))
	defer backend.Close()

	reader := &rangeReader{ctx: context.Background(), fs: New(config.RootFS{}, t.TempDir(), backend.Client()), backendURL: backend.URL}
	count, err := reader.ReadAt(make([]byte, 32768), 32768)
	if count != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("ReadAt() = (%d, %v), want (0, EOF)", count, err)
	}
}

func TestRangeReaderFallsBackWhenBackendIgnoresRange(t *testing.T) {
	requests := 0
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if request.Header.Get("Range") != "bytes=4-7" {
			t.Fatalf("Range = %q", request.Header.Get("Range"))
		}
		_, _ = writer.Write([]byte("fallback"))
	}))
	defer backend.Close()

	reader := &rangeReader{ctx: context.Background(), fs: New(config.RootFS{}, t.TempDir(), backend.Client()), backendURL: backend.URL}
	buffer := make([]byte, 4)
	count, err := reader.ReadAt(buffer, 4)
	if count != 4 || err != nil || string(buffer) != "back" {
		t.Fatalf("ReadAt() = (%d, %q, %v), want (4, back, nil)", count, buffer, err)
	}
	count, err = reader.ReadAt(buffer, 0)
	if count != 4 || err != nil || string(buffer) != "fall" {
		t.Fatalf("ReadAt() = (%d, %q, %v), want (4, fall, nil)", count, buffer, err)
	}
	if requests != 1 {
		t.Fatalf("backend requests = %d, want 1", requests)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}
