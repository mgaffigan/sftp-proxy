package httpfs

// Reading a file over HTTP is one of two entirely different things, and which
// one cannot be known until the backend has been asked. A backend that honours
// RFC 9110 Range requests is read a window at a time and nothing is kept. One
// that answers a range request with the whole file leaves no way to seek within
// the response, so the body is staged on disk and every read is served from
// there.
//
// Rather than one reader carrying the flags for both, each is its own type and
// the first read of a file decides which of them it gets:
//
//	openFile     asks once, then hands every later read to whichever it chose
//	rangeReader  one request per read, holding nothing but the file's length
//	stagedReader one whole-file copy on disk, making no requests at all
//
// openFile serialises that first read. An SFTP client opens a file with a burst
// of pipelined reads, and letting all of them discover an unranged backend at
// once would download the whole file once per read to end up keeping one copy.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"go.opentelemetry.io/otel/trace"

	"sftp-proxy/internal/vfs"
)

// sizeUnknown marks a file whose length no response has stated yet.
const sizeUnknown = -1

// origin is the file as the backend presents it: where it is, and what may be
// spent to reach it. All three readers share the one their file was opened with.
type origin struct {
	ctx        context.Context
	client     *http.Client
	url        string
	stagingDir string
}

// fetch asks for one window of the file. Whether the backend answers with that
// window or with the whole file is for the caller to interpret.
func (o *origin) fetch(offset int64, length int) (*http.Response, error) {
	request, err := http.NewRequest(http.MethodGet, o.url, nil)
	if err != nil {
		return nil, vfs.ErrFailure
	}
	request.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", offset, offset+int64(length)-1))

	response, err := o.client.Do(request.WithContext(o.ctx))
	if err != nil {
		return nil, vfs.ErrFailure
	}
	return response, nil
}

// stage copies a whole-file response to disk. Only a file's first read can
// reach here, so there is never a second copy to reconcile with this one.
func (o *origin) stage(body io.Reader, contentLength int64) (*vfs.StagingFile, error) {
	staged, err := vfs.NewStagingFile(o.stagingDir, "download-*")
	if err != nil {
		return nil, vfs.ErrFailure
	}
	count, err := io.Copy(staged, body)
	if err != nil || contentLength >= 0 && count != contentLength {
		_ = staged.Close()
		return nil, vfs.ErrFailure
	}
	return staged, nil
}

// opaque records a cause that must not travel to the client and returns the
// outcome that may. An io.ReaderAt handed to pkg/sftp bypasses the mapping every
// other handler return passes through, and an unrecognised error's text goes on
// the wire as it is: a backend address from a dropped connection, or the staging
// file's path.
func (o *origin) opaque(err error) error {
	trace.SpanFromContext(o.ctx).RecordError(err)
	return vfs.ErrFailure
}

// openFile is the handle Open hands back. It owns the one question that must be
// answered before any read can be served — whether this backend honours ranges
// — asks it exactly once, and afterwards only forwards.
type openFile struct {
	origin *origin

	mu      sync.Mutex
	chosen  vfs.ReaderAtCloser
	probing chan struct{}
	closed  bool
}

func (f *openFile) ReadAt(destination []byte, offset int64) (int, error) {
	if len(destination) == 0 {
		return 0, nil
	}
	for {
		chosen, gate, err := f.next()
		switch {
		case err != nil:
			return 0, err
		case chosen != nil:
			return chosen.ReadAt(destination, offset)
		case gate != nil:
			// Someone else is asking. Wait for what they learn rather than
			// asking the same question concurrently.
			select {
			case <-gate:
			case <-f.origin.ctx.Done():
				return 0, vfs.ErrFailure
			}
		default:
			return f.probe(destination, offset)
		}
	}
}

// Size reports the file's length by making the read that settles how this file
// is served. Which reader a file gets — and with it what is known about its
// length — is decided by its first read, so asking here is asking that read to
// happen rather than opening a second way to decide the same thing.
func (f *openFile) Size() (int64, error) {
	// An empty file answers the probe with EOF, having still chosen a reader.
	var probe [1]byte
	if _, err := f.ReadAt(probe[:], 0); err != nil && !errors.Is(err, io.EOF) {
		return 0, err
	}

	f.mu.Lock()
	chosen := f.chosen
	f.mu.Unlock()
	if chosen == nil {
		return 0, vfs.ErrFailure
	}
	return chosen.Size()
}

// next decides, under the lock, how a read proceeds: through the reader already
// chosen, waiting on a first read in flight, or as that first read. Becoming it
// is recorded here, so only ever one read does.
func (f *openFile) next() (vfs.ReaderAtCloser, <-chan struct{}, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case f.closed:
		return nil, nil, vfs.ErrFailure
	case f.chosen != nil:
		return f.chosen, nil, nil
	case f.probing != nil:
		return nil, f.probing, nil
	default:
		f.probing = make(chan struct{})
		return nil, nil, nil
	}
}

// probe makes the first read, then lets the reads waiting behind it through
// however it ended. One that failed for reasons of its own has settled nothing,
// so the next read asks again.
func (f *openFile) probe(destination []byte, offset int64) (int, error) {
	count, err := f.classify(destination, offset)

	f.mu.Lock()
	gate := f.probing
	f.probing = nil
	f.mu.Unlock()
	close(gate)
	return count, err
}

// classify reads the file's first window and chooses a reader from how the
// backend answers. That answer is the caller's data as much as it is the
// decision, so the read is served from here rather than made a second time.
func (f *openFile) classify(destination []byte, offset int64) (int, error) {
	response, err := f.origin.fetch(offset, len(destination))
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()

	// The whole file, for a request that asked for part of it. Nothing can seek
	// within a response, so it goes to disk and is read from there ever after.
	if response.StatusCode == http.StatusOK {
		staged, err := f.origin.stage(response.Body, response.ContentLength)
		if err != nil {
			return 0, err
		}
		reader := &stagedReader{origin: f.origin, staged: staged}
		if err := f.adopt(reader); err != nil {
			return 0, err
		}
		return reader.ReadAt(destination, offset)
	}

	// Anything else is a range answered as a range — including a refusal, which
	// is itself proof the backend read the header.
	reader := newRangeReader(f.origin)
	count, err := reader.serve(response, destination)
	if err != nil && !errors.Is(err, io.EOF) {
		return count, err
	}
	if err := f.adopt(reader); err != nil {
		return 0, err
	}
	return count, err
}

// adopt takes on the reader that will serve every later read. A handle closed
// while the first read was still in flight takes on nothing: the reader is
// closed here instead, so a staged copy cannot outlive the handle that made it.
func (f *openFile) adopt(reader vfs.ReaderAtCloser) error {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		_ = reader.Close()
		return vfs.ErrFailure
	}
	f.chosen = reader
	f.mu.Unlock()
	return nil
}

// Close releases whichever reader was chosen. A first read still in flight is
// not waited for; it finds the handle closed when it goes to adopt, and closes
// what it built itself.
func (f *openFile) Close() error {
	f.mu.Lock()
	chosen := f.chosen
	f.chosen, f.closed = nil, true
	f.mu.Unlock()
	if chosen == nil {
		return nil
	}
	return chosen.Close()
}

// rangeReader serves every read with its own range request and keeps nothing
// but the file's length. That length is what makes it cheap: SFTP clients read
// ahead past the end of a file, and those reads are answered here rather than
// sent on to be refused.
type rangeReader struct {
	origin *origin
	size   atomic.Int64
}

func newRangeReader(origin *origin) *rangeReader {
	reader := &rangeReader{origin: origin}
	reader.size.Store(sizeUnknown)
	return reader
}

func (r *rangeReader) ReadAt(destination []byte, offset int64) (int, error) {
	if size := r.size.Load(); size != sizeUnknown && offset >= size {
		return 0, io.EOF
	}
	response, err := r.origin.fetch(offset, len(destination))
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	return r.serve(response, destination)
}

// serve answers one read from a response already in hand, which is how the same
// code serves both an ordinary read and the first one, made before this reader
// was chosen.
func (r *rangeReader) serve(response *http.Response, destination []byte) (int, error) {
	switch response.StatusCode {
	case http.StatusPartialContent:
		r.learn(response)
		count, err := io.ReadFull(response.Body, destination)
		switch {
		case err == nil:
			return count, nil
		case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
			// A range the backend clamped at the end of the file comes back
			// short of what was asked for.
			return count, io.EOF
		default:
			return count, r.origin.opaque(err)
		}
	case http.StatusRequestedRangeNotSatisfiable:
		// A client reading to the end asks one range past it.
		r.learn(response)
		return 0, io.EOF
	case http.StatusOK:
		// A backend that served one range as a range and now answers with the
		// whole file. Staging it is the other reader's job, and this file did
		// not get that reader; there is nothing this one can do with a body it
		// cannot seek within.
		return 0, vfs.ErrFailure
	default:
		if err := responseError(response.StatusCode); err != nil {
			return 0, err
		}
		return 0, vfs.ErrFailure
	}
}

// learn takes the file's length from a response that stated one. The first such
// response wins: a later one disagreeing cannot be allowed to shorten the file
// under reads already in flight. A response stating nothing swaps in the value
// already there and so changes nothing.
func (r *rangeReader) learn(response *http.Response) {
	r.size.CompareAndSwap(sizeUnknown, contentRangeTotal(response.Header.Get("Content-Range")))
}

// Size reports what a response stated the file's complete length to be. A
// backend that never states one leaves this reader with nothing to report: the
// length can only be discovered by downloading the whole file, which is the
// other reader's bargain, not this one's.
func (r *rangeReader) Size() (int64, error) {
	size := r.size.Load()
	if size == sizeUnknown {
		return 0, vfs.ErrUnsupported
	}
	return size, nil
}

func (r *rangeReader) Close() error { return nil }

// stagedReader serves reads from the whole-file copy on disk that was made when
// the backend answered a range request with the entire file. It never asks the
// backend for anything.
type stagedReader struct {
	origin *origin
	staged *vfs.StagingFile
}

func (s *stagedReader) ReadAt(destination []byte, offset int64) (int, error) {
	count, err := s.staged.ReadAt(destination, offset)
	if err == nil || errors.Is(err, io.EOF) {
		return count, err
	}
	return count, s.origin.opaque(err)
}

// Size is exact here, and free: the whole file is already on disk.
func (s *stagedReader) Size() (int64, error) {
	info, err := s.staged.Stat()
	if err != nil {
		return 0, s.origin.opaque(err)
	}
	return info.Size(), nil
}

func (s *stagedReader) Close() error { return s.staged.Close() }

// contentRangeTotal reports the complete length a Content-Range header states,
// or sizeUnknown when the header is absent, malformed, or leaves the total
// unstated. Both forms a read can meet are accepted: "bytes 0-511/1024" on a
// partial response and "bytes */1024" on a refused range.
//
// Not knowing costs only the requests a known length would have saved, so
// anything unrecognised is treated as unstated rather than as an error.
func contentRangeTotal(header string) int64 {
	unit, remainder, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(strings.TrimSpace(unit), "bytes") {
		return sizeUnknown
	}
	_, total, found := strings.Cut(remainder, "/")
	if !found {
		return sizeUnknown
	}
	size, err := strconv.ParseInt(strings.TrimSpace(total), 10, 64)
	if err != nil || size < 0 {
		return sizeUnknown
	}
	return size
}

var (
	_ vfs.ReaderAtCloser = (*openFile)(nil)
	_ vfs.ReaderAtCloser = (*rangeReader)(nil)
	_ vfs.ReaderAtCloser = (*stagedReader)(nil)
)
