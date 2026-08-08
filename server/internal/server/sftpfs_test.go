package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"sftp-proxy/internal/config"
	"sftp-proxy/internal/httpfs"
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

func (testWriteBackend) Rename(context.Context, vfs.Node, string) error {
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
