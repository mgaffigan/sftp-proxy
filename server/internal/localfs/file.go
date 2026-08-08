package localfs

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"go.opentelemetry.io/otel/trace"

	"sftp-proxy/internal/vfs"
)

// uploadPrefix names a file being written. It is hidden, and left out of
// listings, so a client never sees one and cannot ask for one by name.
const uploadPrefix = ".sftp-proxy-upload-"

// uploadAttempts bounds the search for an unused upload name. A collision needs
// two of 128 random bits to agree, so the retry is insurance rather than a loop
// that ever runs twice.
const uploadAttempts = 3

// outcome translates what the operating system reports into what a caller may
// see. Every os error names the path it happened to, and an error returned
// through io.ReaderAt reaches an SFTP client as its own text, so nothing but
// these fixed values may leave this package.
//
// A refusal to leave the root arrives here as a generic failure, which is all a
// client learns of it; the cause is recorded on the span instead.
func outcome(ctx context.Context, err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, fs.ErrNotExist):
		return vfs.ErrNotExist
	case errors.Is(err, fs.ErrPermission):
		return vfs.ErrPermission
	case errors.Is(err, fs.ErrExist):
		return vfs.ErrExist
	default:
		trace.SpanFromContext(ctx).RecordError(err)
		return vfs.ErrFailure
	}
}

// localFile is an open file, wrapped so that its length can be asked for and so
// that what os reports about it stays here.
type localFile struct {
	ctx  context.Context
	file *os.File
}

func (f localFile) ReadAt(destination []byte, offset int64) (int, error) {
	count, err := f.file.ReadAt(destination, offset)
	if err == nil || errors.Is(err, io.EOF) {
		return count, err
	}
	return count, outcome(f.ctx, err)
}

// Size is exact and free: the file is already open.
func (f localFile) Size() (int64, error) {
	info, err := f.file.Stat()
	if err != nil {
		return 0, outcome(f.ctx, err)
	}
	return info.Size(), nil
}

func (f localFile) Close() error { return outcome(f.ctx, f.file.Close()) }

// upload is a file being written, and is not the file the client named.
//
// Writes go to a hidden name beside it and the whole of them is renamed over it
// at the end, which is one indivisible step. Writing in place would publish a
// partial file under a name another process may already be watching for, and
// would leave a truncated one there if the transfer were abandoned. SFTP writes
// arrive at arbitrary offsets in whatever order the client chooses, and a file
// on disk takes them as they come, so nothing needs staging elsewhere first.
type upload struct {
	ctx       context.Context
	at        location
	file      *os.File
	temporary string
	err       error
}

func newUpload(ctx context.Context, at location) (*upload, error) {
	directory := filepath.Dir(at.rel)
	for range uploadAttempts {
		temporary := filepath.Join(directory, uploadPrefix+rand.Text())
		file, err := at.root.OpenFile(temporary, os.O_RDWR|os.O_CREATE|os.O_EXCL, createFileMode)
		switch {
		case errors.Is(err, fs.ErrExist):
			continue
		case err != nil:
			return nil, outcome(ctx, err)
		}
		return &upload{ctx: ctx, at: at, file: file, temporary: temporary}, nil
	}
	return nil, vfs.ErrFailure
}

func (u *upload) WriteAt(data []byte, offset int64) (int, error) {
	if u.err != nil {
		return 0, u.err
	}
	count, err := u.file.WriteAt(data, offset)
	if err != nil {
		u.err = outcome(u.ctx, err)
		return count, u.err
	}
	return count, nil
}

// Close publishes what was written. A name that was already taken keeps its old
// contents until the whole of the new ones are ready to replace them.
func (u *upload) Close() error {
	if u.err != nil {
		_ = u.discard()
		return u.err
	}
	u.err = vfs.ErrFailure // no further writes, whichever way this goes
	if err := u.file.Close(); err != nil {
		_ = u.at.root.Remove(u.temporary)
		return outcome(u.ctx, err)
	}
	if err := u.at.root.Rename(u.temporary, u.at.rel); err != nil {
		_ = u.at.root.Remove(u.temporary)
		return outcome(u.ctx, err)
	}
	return nil
}

// Abort discards what was written instead of publishing it. A transfer the
// client gave up on has nothing worth keeping, and whatever was already at that
// name is untouched: nothing was ever written to it.
func (u *upload) Abort() error {
	if u.err != nil {
		return nil
	}
	u.err = vfs.ErrFailure
	return u.discard()
}

func (u *upload) discard() error {
	closed := u.file.Close()
	removed := u.at.root.Remove(u.temporary)
	if closed != nil || removed != nil {
		return outcome(u.ctx, errors.Join(closed, removed))
	}
	return nil
}

var (
	_ vfs.ReaderAtCloser = localFile{}
	_ vfs.WriterAtCloser = (*upload)(nil)
)
