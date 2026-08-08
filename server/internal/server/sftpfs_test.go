package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"sftp-proxy/internal/config"
	"sftp-proxy/internal/httpfs"
	"sftp-proxy/internal/localfs"
	"sftp-proxy/internal/vfs"
)

func TestFilesystemOutcomesBecomeSFTPStatuses(t *testing.T) {
	cases := []struct {
		from error
		want error
	}{
		{vfs.ErrNotExist, sftp.ErrSSHFxNoSuchFile},
		{vfs.ErrPermission, sftp.ErrSSHFxPermissionDenied},
		{vfs.ErrUnsupported, sftp.ErrSSHFxOpUnsupported},
		{vfs.ErrFailure, sftp.ErrSSHFxFailure},
		{vfs.ErrExist, sftp.ErrSSHFxFailure},
		// Anything unrecognised must not travel as itself: pkg/sftp puts a bare
		// error's text on the wire, where it would describe the backend to a
		// client that must not learn about it.
		{errors.New("dial tcp 10.0.0.7:443: connect: refused"), sftp.ErrSSHFxFailure},
	}
	for _, testCase := range cases {
		got := statusError(testCase.from)
		if !errors.Is(got, testCase.want) {
			t.Errorf("statusError(%v) = %v, want %v", testCase.from, got, testCase.want)
		}
	}
	if statusError(nil) != nil {
		t.Errorf("statusError(nil) = %v, want nil", statusError(nil))
	}
}

func TestNodesBecomeFileInfo(t *testing.T) {
	permissions := uint32(0640)
	mtime := time.Date(2026, time.August, 7, 12, 34, 56, 0, time.UTC)
	file := fileInfoFor(vfs.Node{File: "report.txt", Size: 42, Permissions: &permissions, Mtime: &mtime})
	if file.Name() != "report.txt" || file.Size() != 42 || file.IsDir() {
		t.Errorf("file info = %+v", file)
	}
	if file.Mode().IsDir() || file.Mode().Perm() != 0640 {
		t.Errorf("file mode = %v", file.Mode())
	}
	if !file.ModTime().Equal(mtime) {
		t.Errorf("file modification time = %v, want %v", file.ModTime(), mtime)
	}

	directory := fileInfoFor(vfs.Node{Directory: "outbound"})
	if directory.Name() != "outbound" || !directory.IsDir() {
		t.Errorf("directory info = %+v", directory)
	}
	if !directory.Mode().IsDir() || directory.Mode().Perm() != 0777 {
		t.Errorf("directory mode = %v", directory.Mode())
	}
	if !directory.ModTime().IsZero() {
		t.Errorf("directory modification time = %v, want zero", directory.ModTime())
	}
}

func TestListerWalksAndEndsAtEOF(t *testing.T) {
	entries := lister{entries: []os.FileInfo{
		fileInfoFor(vfs.Node{File: "a"}),
		fileInfoFor(vfs.Node{File: "b"}),
		fileInfoFor(vfs.Node{File: "c"}),
	}}

	target := make([]os.FileInfo, 2)
	count, err := entries.ListAt(target, 0)
	if count != 2 || err != nil {
		t.Fatalf("ListAt(0) = (%d, %v), want (2, nil)", count, err)
	}
	if target[0].Name() != "a" || target[1].Name() != "b" {
		t.Fatalf("first page = %v, %v", target[0].Name(), target[1].Name())
	}

	// A short final page reports EOF along with what it filled.
	count, err = entries.ListAt(target, 2)
	if count != 1 || !errors.Is(err, io.EOF) {
		t.Fatalf("ListAt(2) = (%d, %v), want (1, EOF)", count, err)
	}
	count, err = entries.ListAt(target, 3)
	if count != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("ListAt(3) = (%d, %v), want (0, EOF)", count, err)
	}
}

func TestUnsupportedRequestMethodsAreRefused(t *testing.T) {
	adapter := &sftpFS{fs: vfs.New(config.RootFS{}, nil)}

	if err := adapter.Filecmd(sftp.NewRequest("Symlink", "/a")); !errors.Is(err, sftp.ErrSSHFxOpUnsupported) {
		t.Errorf("Filecmd(Symlink) = %v, want op unsupported", err)
	}
	if _, err := adapter.Filelist(sftp.NewRequest("Readlink", "/a")); !errors.Is(err, sftp.ErrSSHFxOpUnsupported) {
		t.Errorf("Filelist(Readlink) = %v, want op unsupported", err)
	}
}

type testWriter struct{}

func (testWriter) WriteAt(data []byte, offset int64) (int, error) { return len(data), nil }
func (testWriter) Close() error                                   { return nil }
func (testWriter) Abort() error                                   { return nil }

type testWriteBackend struct{}

func (testWriteBackend) List(context.Context, vfs.Node) ([]vfs.Node, error) {
	return nil, vfs.ErrUnsupported
}

func (testWriteBackend) Open(context.Context, vfs.Node) (vfs.ReaderAtCloser, error) {
	return nil, vfs.ErrUnsupported
}

func (testWriteBackend) Create(context.Context, vfs.Node) (vfs.WriterAtCloser, error) {
	return testWriter{}, nil
}

func (testWriteBackend) Mkdir(context.Context, vfs.Node) error  { return vfs.ErrUnsupported }
func (testWriteBackend) Remove(context.Context, vfs.Node) error { return vfs.ErrUnsupported }

func (testWriteBackend) Rename(context.Context, vfs.Node, string, string) error {
	return vfs.ErrUnsupported
}

func (testWriteBackend) Child(vfs.Node, string) (vfs.Node, error) {
	return vfs.Node{}, vfs.ErrUnsupported
}

func TestFilewriteLimitsConcurrentUploads(t *testing.T) {
	filesystem := vfs.New(config.RootFS{Children: []config.Entry{
		{File: "first.txt", Backend: "test://files/first.txt"},
		{File: "second.txt", Backend: "test://files/second.txt"},
	}}, vfs.Backends{"test": testWriteBackend{}})
	adapter := handlers(filesystem, 1).FilePut.(*sftpFS)

	first, err := adapter.Filewrite(sftp.NewRequest("Put", "/first.txt"))
	if err != nil {
		t.Fatalf("first Filewrite() error = %v", err)
	}
	if _, err := adapter.Filewrite(sftp.NewRequest("Put", "/second.txt")); !errors.Is(err, sftp.ErrSSHFxFailure) {
		t.Fatalf("second Filewrite() error = %v, want failure", err)
	}
	closer, ok := first.(io.Closer)
	if !ok {
		t.Fatalf("first writer %T does not close", first)
	}
	if err := closer.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if _, err := adapter.Filewrite(sftp.NewRequest("Put", "/second.txt")); err != nil {
		t.Fatalf("second Filewrite() after Close error = %v", err)
	}
}

func TestReadSpanContainsBackendRequestUntilClose(t *testing.T) {
	previousPropagator := otel.GetTextMapPropagator()
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	t.Cleanup(func() { otel.SetTextMapPropagator(previousPropagator) })

	recorder := tracetest.NewSpanRecorder()
	provider := trace.NewTracerProvider(trace.WithSpanProcessor(recorder))
	t.Cleanup(func() { _ = provider.Shutdown(t.Context()) })
	previousProvider := otel.GetTracerProvider()
	otel.SetTracerProvider(provider)
	t.Cleanup(func() { otel.SetTracerProvider(previousProvider) })
	tracer := provider.Tracer("test")

	var traceparent string
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		traceparent = request.Header.Get("traceparent")
		writer.Header().Set("Content-Length", "2")
		writer.WriteHeader(http.StatusPartialContent)
		_, _ = writer.Write([]byte("ok"))
	}))
	defer backend.Close()

	filesystem := vfs.New(config.RootFS{Children: []config.Entry{{
		File:    "report.txt",
		Backend: backend.URL + "/report.txt",
	}}}, vfs.Backends{"http": httpfs.New(backend.Client(), t.TempDir())})
	connectionCtx, connectionSpan := tracer.Start(context.Background(), "ssh.connection")
	sessionCtx, sessionSpan := tracer.Start(connectionCtx, "sftp.session")
	adapter := newHandlerFactory(filesystem, 0).handlers(sessionCtx).FileGet.(*sftpFS)

	reader, err := adapter.Fileread(sftp.NewRequest("Get", "/report.txt"))
	if err != nil {
		t.Fatal(err)
	}
	contents := make([]byte, 2)
	if count, err := reader.ReadAt(contents, 0); err != nil || count != len(contents) || string(contents) != "ok" {
		t.Fatalf("ReadAt() = (%d, %v, %q), want (2, nil, ok)", count, err, contents)
	}
	if traceparent == "" {
		t.Fatal("backend request has no traceparent header")
	}
	if spanNamed(recorder.Ended(), "sftp.read") != nil {
		t.Fatal("sftp.read span ended before its reader closed")
	}
	if err := reader.(io.Closer).Close(); err != nil {
		t.Fatal(err)
	}
	sessionSpan.End()
	connectionSpan.End()

	spans := recorder.Ended()
	connection := spanNamed(spans, "ssh.connection")
	session := spanNamed(spans, "sftp.session")
	read := spanNamed(spans, "sftp.read")
	request := spanNamed(spans, "HTTP GET")
	if connection == nil || session == nil || read == nil || request == nil {
		t.Fatalf("ended spans = %v, want connection, session, read, and HTTP request", spanNames(spans))
	}
	if session.Parent().SpanID() != connection.SpanContext().SpanID() ||
		read.Parent().SpanID() != session.SpanContext().SpanID() ||
		request.Parent().SpanID() != read.SpanContext().SpanID() {
		t.Fatalf("span parentage = connection=%s session=%s read=%s request=%s", connection.Parent().SpanID(), session.Parent().SpanID(), read.Parent().SpanID(), request.Parent().SpanID())
	}
}

func spanNamed(spans []trace.ReadOnlySpan, name string) trace.ReadOnlySpan {
	for _, span := range spans {
		if span.Name() == name {
			return span
		}
	}
	return nil
}

func spanNames(spans []trace.ReadOnlySpan) []string {
	names := make([]string, 0, len(spans))
	for _, span := range spans {
		names = append(names, span.Name())
	}
	return names
}

// TestSFTPServesLocalFiles drives the local backend the way a client does: the
// SFTP surface, the virtual filesystem, and real files on disk, with nothing
// stubbed in between.
func TestSFTPServesLocalFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "seed.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	local, err := localfs.New([]string{root})
	if err != nil {
		t.Fatalf("localfs.New() error = %v", err)
	}
	t.Cleanup(func() { _ = local.Close() })

	filesystem := vfs.New(config.RootFS{Children: []config.Entry{{
		Directory: "Files",
		Backend:   (&url.URL{Scheme: config.FileScheme, Path: root}).String(),
	}}}, vfs.Backends{config.FileScheme: local})
	adapter := newHandlerFactory(filesystem, 0).handlers(context.Background()).FileGet.(*sftpFS)

	entries := listing(t, adapter, "/Files")
	if len(entries) != 1 || entries[0].Name() != "seed.txt" || entries[0].Size() != 5 {
		t.Fatalf("listing = %v", entries)
	}
	if entries[0].Mode().Perm() != 0o644 {
		t.Errorf("mode = %v, want the file's own permissions", entries[0].Mode())
	}

	reader, err := adapter.Fileread(sftp.NewRequest("Get", "/Files/seed.txt"))
	if err != nil {
		t.Fatalf("Fileread() error = %v", err)
	}
	contents := make([]byte, 5)
	if _, err := reader.ReadAt(contents, 0); err != nil || string(contents) != "hello" {
		t.Fatalf("ReadAt() = (%q, %v)", contents, err)
	}
	if err := reader.(io.Closer).Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	writer, err := adapter.Filewrite(sftp.NewRequest("Put", "/Files/upload.txt"))
	if err != nil {
		t.Fatalf("Filewrite() error = %v", err)
	}
	if _, err := writer.WriteAt([]byte("uploaded"), 0); err != nil {
		t.Fatalf("WriteAt() error = %v", err)
	}
	if err := writer.(io.Closer).Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if contents, err := os.ReadFile(filepath.Join(root, "upload.txt")); err != nil || string(contents) != "uploaded" {
		t.Fatalf("upload.txt = (%q, %v)", contents, err)
	}

	if err := adapter.Filecmd(sftp.NewRequest("Mkdir", "/Files/Archive")); err != nil {
		t.Fatalf("Mkdir error = %v", err)
	}

	// A client that uploads under a temporary name and renames it into place,
	// which is what the rename this backend supports is for.
	rename := sftp.NewRequest("Rename", "/Files/upload.txt")
	rename.Target = "/Files/report.txt"
	if err := adapter.Filecmd(rename); err != nil {
		t.Fatalf("Rename error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "report.txt")); err != nil {
		t.Fatalf("report.txt = %v", err)
	}

	// Somewhere else is somewhere this backend cannot place it.
	elsewhere := sftp.NewRequest("Rename", "/Files/report.txt")
	elsewhere.Target = "/Files/Archive/report.txt"
	if err := adapter.Filecmd(elsewhere); !errors.Is(err, sftp.ErrSSHFxOpUnsupported) {
		t.Fatalf("Rename into another directory = %v, want op unsupported", err)
	}

	if err := adapter.Filecmd(sftp.NewRequest("Remove", "/Files/report.txt")); err != nil {
		t.Fatalf("Remove error = %v", err)
	}
	if err := adapter.Filecmd(sftp.NewRequest("Rmdir", "/Files/Archive")); err != nil {
		t.Fatalf("Rmdir error = %v", err)
	}
	entries = listing(t, adapter, "/Files")
	if len(entries) != 1 || entries[0].Name() != "seed.txt" {
		t.Fatalf("listing after removal = %v", entries)
	}

	// A link out of the allowed directory is not offered to a client, and naming
	// it anyway reaches nothing.
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("not yours"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	if entries := listing(t, adapter, "/Files"); len(entries) != 1 || entries[0].Name() != "seed.txt" {
		t.Fatalf("listing with a link present = %v", entries)
	}
	if _, err := adapter.Fileread(sftp.NewRequest("Get", "/Files/escape/secret.txt")); !errors.Is(err, sftp.ErrSSHFxNoSuchFile) {
		t.Fatalf("read through a link out of the allowed directory = %v, want no such file", err)
	}
}

func listing(t *testing.T, adapter *sftpFS, path string) []os.FileInfo {
	t.Helper()
	lister, err := adapter.Filelist(sftp.NewRequest("List", path))
	if err != nil {
		t.Fatalf("Filelist(%q) error = %v", path, err)
	}
	entries := make([]os.FileInfo, 8)
	count, err := lister.ListAt(entries, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("ListAt() error = %v", err)
	}
	return entries[:count]
}

// TestAnInterruptedTransferDiscardsTheUpload covers what a dropped connection
// looks like from here: pkg/sftp reports the failure on the handle and then
// closes it, and a close on its own would publish whatever had arrived.
func TestAnInterruptedTransferDiscardsTheUpload(t *testing.T) {
	root := t.TempDir()
	local, err := localfs.New([]string{root})
	if err != nil {
		t.Fatalf("localfs.New() error = %v", err)
	}
	t.Cleanup(func() { _ = local.Close() })

	filesystem := vfs.New(config.RootFS{
		Backend: (&url.URL{Scheme: config.FileScheme, Path: root}).String(),
	}, vfs.Backends{config.FileScheme: local})
	adapter := newHandlerFactory(filesystem, 0).handlers(context.Background()).FilePut.(*sftpFS)

	writer, err := adapter.Filewrite(sftp.NewRequest("Put", "/half.txt"))
	if err != nil {
		t.Fatalf("Filewrite() error = %v", err)
	}
	if _, err := writer.WriteAt([]byte("half a file"), 0); err != nil {
		t.Fatalf("WriteAt() error = %v", err)
	}

	failed, ok := writer.(sftp.TransferError)
	if !ok {
		t.Fatalf("writer %T does not report a transfer error", writer)
	}
	failed.TransferError(io.ErrUnexpectedEOF)
	// The close pkg/sftp makes next must not undo that.
	if err := writer.(io.Closer).Close(); err == nil {
		t.Error("Close() after a failed transfer reported success")
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("%s contains %d entries, want the upload discarded", root, len(entries))
	}
}
