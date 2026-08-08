package server

import (
	"errors"
	"io"
	"os"
	"sync"
	"time"

	"github.com/pkg/sftp"

	"sftp-proxy/internal/vfs"
)

// sftpFS maps SFTP requests onto virtual filesystem operations. It is the only
// place that knows about the SFTP protocol; everything below it deals in paths
// and nodes.
type sftpFS struct {
	fs      *vfs.FS
	uploads chan struct{}
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

func handlers(filesystem *vfs.FS, maxConcurrentUploads int) sftp.Handlers {
	adapter := &sftpFS{fs: filesystem}
	if maxConcurrentUploads > 0 {
		adapter.uploads = make(chan struct{}, maxConcurrentUploads)
	}
	return sftp.Handlers{FileGet: adapter, FilePut: adapter, FileCmd: adapter, FileList: adapter}
}

func (s *sftpFS) Fileread(request *sftp.Request) (io.ReaderAt, error) {
	reader, err := s.fs.Open(request.Context(), request.Filepath)
	if err != nil {
		return nil, statusError(err)
	}
	return reader, nil
}

func (s *sftpFS) Filewrite(request *sftp.Request) (io.WriterAt, error) {
	if s.uploads == nil {
		writer, err := s.fs.Create(request.Context(), request.Filepath)
		if err != nil {
			return nil, statusError(err)
		}
		return writer, nil
	}

	select {
	case s.uploads <- struct{}{}:
	default:
		return nil, statusError(vfs.ErrFailure)
	}
	writer, err := s.fs.Create(request.Context(), request.Filepath)
	if err != nil {
		<-s.uploads
		return nil, statusError(err)
	}
	return &uploadWriter{WriterAtCloser: writer, release: func() { <-s.uploads }}, nil
}

func (s *sftpFS) Filecmd(request *sftp.Request) error {
	ctx := request.Context()
	switch request.Method {
	case "Setstat":
		// Permission, owner, and timestamp updates succeed as no-ops, but only
		// for a path that exists.
		_, err := s.fs.Stat(ctx, request.Filepath)
		return statusError(err)
	case "Mkdir":
		return statusError(s.fs.Mkdir(ctx, request.Filepath))
	case "Remove", "Rmdir":
		return statusError(s.fs.Remove(ctx, request.Filepath))
	case "Rename":
		return statusError(s.fs.Rename(ctx, request.Filepath, request.Target))
	default:
		return sftp.ErrSSHFxOpUnsupported
	}
}

func (s *sftpFS) Filelist(request *sftp.Request) (sftp.ListerAt, error) {
	switch request.Method {
	case "Stat":
		node, err := s.fs.Stat(request.Context(), request.Filepath)
		if err != nil {
			return nil, statusError(err)
		}
		return lister{entries: []os.FileInfo{fileInfoFor(node)}}, nil
	case "List":
		children, err := s.fs.List(request.Context(), request.Filepath)
		if err != nil {
			return nil, statusError(err)
		}
		entries := make([]os.FileInfo, 0, len(children))
		for _, child := range children {
			entries = append(entries, fileInfoFor(child))
		}
		return lister{entries: entries}, nil
	default:
		return nil, sftp.ErrSSHFxOpUnsupported
	}
}

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
