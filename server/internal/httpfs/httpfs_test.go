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
