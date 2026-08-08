package server

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"sftp-proxy/internal/telemetry"
	"sftp-proxy/internal/vfs"
)

// sftpFS maps SFTP requests onto virtual filesystem operations. It is the only
// place that knows about the SFTP protocol; everything below it deals in paths
// and nodes.
type sftpFS struct {
	fs         *vfs.FS
	uploads    *uploadLimiter
	sessionCtx context.Context
}

type handlerFactory struct {
	fs      *vfs.FS
	uploads *uploadLimiter
}

// uploadLimiter caps the uploads one connection may have open at once.
// maxConcurrentUploads is a property of the user rather than of any one session,
// so a single limiter is shared by every channel on the connection, whichever
// protocol that channel speaks. A nil limiter imposes no limit at all.
type uploadLimiter struct {
	slots chan struct{}
}

func newUploadLimiter(maxConcurrentUploads int) *uploadLimiter {
	if maxConcurrentUploads <= 0 {
		return nil
	}
	return &uploadLimiter{slots: make(chan struct{}, maxConcurrentUploads)}
}

// acquire takes a slot without waiting for one, reporting whether it got it. An
// upload that has to queue is an upload the client is already holding a handle
// open for, so refusing is the answer, not blocking.
func (l *uploadLimiter) acquire() (release func(), ok bool) {
	if l == nil {
		return func() {}, true
	}
	select {
	case l.slots <- struct{}{}:
		return func() { <-l.slots }, true
	default:
		return nil, false
	}
}

type uploadWriter struct {
	vfs.WriterAtCloser
	release func()
	once    sync.Once
}

func (w *uploadWriter) Close() error {
	err := w.WriterAtCloser.Close()
	w.once.Do(w.release)
	return err
}

func (w *uploadWriter) Abort() error {
	err := w.WriterAtCloser.Abort()
	w.once.Do(w.release)
	return err
}

func handlers(filesystem *vfs.FS, maxConcurrentUploads int) sftp.Handlers {
	return newHandlerFactory(filesystem, maxConcurrentUploads).handlers(context.Background())
}

func newHandlerFactory(filesystem *vfs.FS, maxConcurrentUploads int) *handlerFactory {
	return &handlerFactory{fs: filesystem, uploads: newUploadLimiter(maxConcurrentUploads)}
}

func (f *handlerFactory) handlers(sessionCtx context.Context) sftp.Handlers {
	adapter := &sftpFS{fs: f.fs, uploads: f.uploads, sessionCtx: sessionCtx}
	return sftp.Handlers{FileGet: adapter, FilePut: adapter, FileCmd: adapter, FileList: adapter}
}

func (s *sftpFS) Fileread(request *sftp.Request) (io.ReaderAt, error) {
	ctx, finish := s.startOperation(request, "read")
	reader, err := s.fs.Open(ctx, request.Filepath)
	if err != nil {
		finish(err)
		return nil, statusError(err)
	}
	return &tracedReader{ReaderAtCloser: reader, span: trace.SpanFromContext(ctx), finish: finish}, nil
}

func (s *sftpFS) Filewrite(request *sftp.Request) (io.WriterAt, error) {
	// We don't support append (s3 is immutable)
	if request.Pflags().Append {
		return nil, sftp.ErrSSHFxOpUnsupported
	}
	ctx, finish := s.startOperation(request, "write")
	release, ok := s.uploads.acquire()
	if !ok {
		finish(vfs.ErrFailure)
		return nil, statusError(vfs.ErrFailure)
	}
	writer, err := s.fs.Create(ctx, request.Filepath)
	if err != nil {
		release()
		finish(err)
		return nil, statusError(err)
	}
	return &tracedWriter{
		WriterAtCloser: &uploadWriter{WriterAtCloser: writer, release: release},
		span:           trace.SpanFromContext(ctx),
		finish:         finish,
	}, nil
}

func (s *sftpFS) Filecmd(request *sftp.Request) error {
	operation := map[string]string{
		"Setstat": "setstat",
		"Mkdir":   "mkdir",
		"Remove":  "remove",
		"Rmdir":   "remove",
		"Rename":  "rename",
	}[request.Method]
	if operation == "" {
		return sftp.ErrSSHFxOpUnsupported
	}
	ctx, finish := s.startOperation(request, operation)
	var err error
	switch request.Method {
	case "Setstat":
		// Permission, owner, and timestamp updates succeed as no-ops, but only
		// for a path that exists.
		_, err = s.fs.Stat(ctx, request.Filepath)
	case "Mkdir":
		err = s.fs.Mkdir(ctx, request.Filepath)
	case "Remove", "Rmdir":
		err = s.fs.Remove(ctx, request.Filepath)
	case "Rename":
		err = s.fs.Rename(ctx, request.Filepath, request.Target)
	}
	finish(err)
	return statusError(err)
}

func (s *sftpFS) Filelist(request *sftp.Request) (sftp.ListerAt, error) {
	operation := map[string]string{"Stat": "stat", "List": "list"}[request.Method]
	if operation == "" {
		return nil, sftp.ErrSSHFxOpUnsupported
	}
	ctx, finish := s.startOperation(request, operation)
	switch request.Method {
	case "Stat":
		node, err := s.fs.Stat(ctx, request.Filepath)
		if err != nil {
			finish(err)
			return nil, statusError(err)
		}
		finish(nil)
		return lister{entries: []os.FileInfo{fileInfoFor(node)}}, nil
	case "List":
		children, err := s.fs.List(ctx, request.Filepath)
		if err != nil {
			finish(err)
			return nil, statusError(err)
		}
		entries := make([]os.FileInfo, 0, len(children))
		for _, child := range children {
			entries = append(entries, fileInfoFor(child))
		}
		finish(nil)
		return lister{entries: entries}, nil
	}
	return nil, sftp.ErrSSHFxOpUnsupported
}

func (s *sftpFS) startOperation(request *sftp.Request, operation string) (context.Context, func(error)) {
	parent := s.sessionCtx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(request.Context(), cancel)
	ctx, span := telemetry.Tracer().Start(ctx, "sftp."+operation,
		trace.WithAttributes(attribute.String("sftp.operation", operation)))
	var once sync.Once
	return ctx, func(err error) {
		once.Do(func() {
			recordOperationError(span, err)
			span.End()
			stop()
			cancel()
		})
	}
}

func recordOperationError(span trace.Span, err error) {
	if err == nil || errors.Is(err, io.EOF) {
		return
	}
	classification := "failure"
	switch {
	case errors.Is(err, vfs.ErrNotExist):
		classification = "not_found"
	case errors.Is(err, vfs.ErrPermission):
		classification = "permission"
	case errors.Is(err, vfs.ErrUnsupported):
		classification = "unsupported"
	}
	span.SetStatus(codes.Error, "SFTP operation failed")
	span.SetAttributes(attribute.String("error.type", classification))
}

type tracedReader struct {
	vfs.ReaderAtCloser
	span   trace.Span
	finish func(error)
}

func (r *tracedReader) ReadAt(destination []byte, offset int64) (int, error) {
	count, err := r.ReaderAtCloser.ReadAt(destination, offset)
	recordOperationError(r.span, err)
	return count, err
}

func (r *tracedReader) Close() error {
	err := r.ReaderAtCloser.Close()
	r.finish(err)
	return err
}

type tracedWriter struct {
	vfs.WriterAtCloser
	span   trace.Span
	finish func(error)
}

func (w *tracedWriter) WriteAt(data []byte, offset int64) (int, error) {
	count, err := w.WriterAtCloser.WriteAt(data, offset)
	recordOperationError(w.span, err)
	return count, err
}

func (w *tracedWriter) Close() error {
	err := w.WriterAtCloser.Close()
	w.finish(err)
	return err
}

// Abort ends the operation as the failure it is: the client gave up on this
// upload, whether or not discarding what had been staged went cleanly.
func (w *tracedWriter) Abort() error {
	err := w.WriterAtCloser.Abort()
	w.finish(vfs.ErrFailure)
	return err
}

// TransferError is how pkg/sftp reports a transfer that ended badly — a dropped
// connection, a client that stopped — on the handle it is about to close. The
// close alone says nothing of the failure, so without this the partial content
// that arrived would be published as though it were the whole file.
func (w *tracedWriter) TransferError(error) { _ = w.Abort() }

var _ sftp.TransferError = (*tracedWriter)(nil)

// statusError translates a filesystem outcome into the SFTP status a client
// receives. Anything unrecognised becomes a generic failure: pkg/sftp puts a
// bare error's text on the wire, so only these fixed values may reach it.
func statusError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, vfs.ErrNotExist):
		return sftp.ErrSSHFxNoSuchFile
	case errors.Is(err, vfs.ErrPermission):
		return sftp.ErrSSHFxPermissionDenied
	case errors.Is(err, vfs.ErrUnsupported):
		return sftp.ErrSSHFxOpUnsupported
	default:
		return sftp.ErrSSHFxFailure
	}
}

type lister struct {
	entries []os.FileInfo
}

func (l lister) ListAt(target []os.FileInfo, offset int64) (int, error) {
	if offset >= int64(len(l.entries)) {
		return 0, io.EOF
	}
	count := copy(target, l.entries[offset:])
	if count < len(target) {
		return count, io.EOF
	}
	return count, nil
}

// fileInfo is the SFTP view of a node. The mode carries no policy — what a
// client may do is decided by the backend, not advertised here — so it states
// only whether the node is a directory.
type fileInfo struct {
	name  string
	size  int64
	mode  os.FileMode
	mtime time.Time
	isDir bool
}

func fileInfoFor(node vfs.Node) fileInfo {
	mode := os.FileMode(0666)
	if node.IsDirectory() {
		mode = os.ModeDir | 0777
	}
	if node.Permissions != nil {
		mode = mode.Type() | os.FileMode(*node.Permissions)
	}
	mtime := time.Time{}
	if node.Mtime != nil {
		mtime = *node.Mtime
	}
	return fileInfo{name: node.Name(), size: node.Size, mode: mode, mtime: mtime, isDir: node.IsDirectory()}
}

func (f fileInfo) Name() string       { return f.name }
func (f fileInfo) Size() int64        { return f.size }
func (f fileInfo) Mode() os.FileMode  { return f.mode }
func (f fileInfo) ModTime() time.Time { return f.mtime }
func (f fileInfo) IsDir() bool        { return f.isDir }
func (f fileInfo) Sys() any           { return nil }
