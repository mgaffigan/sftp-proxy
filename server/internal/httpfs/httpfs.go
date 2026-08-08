// Package httpfs serves virtual filesystem nodes over the HTTP backend
// contract: GET lists a directory or reads a file, POST creates, DELETE
// removes, and DELETE with a renameTo query moves.
package httpfs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"sftp-proxy/internal/config"
	"sftp-proxy/internal/vfs"
)

const directoryContentType = "application/vnd.sftproxy.directory+json"
const directoryEntryContentType = "application/vnd.sftpproxy.directoryentry"
const uploadContentType = "application/octet-stream"

// maxListingBytes bounds a directory listing response.
const maxListingBytes = 8 << 20

type Backend struct {
	client     *http.Client
	stagingDir string
}

func New(client *http.Client, stagingDir string) *Backend {
	return &Backend{client: client, stagingDir: stagingDir}
}

func (b *Backend) List(ctx context.Context, node vfs.Node) ([]vfs.Node, error) {
	// A directory that does not permit GET is presented as empty rather than
	// asked about, which is the point of declaring allowed_methods: it keeps
	// traffic off a backend that would only refuse it.
	if !permits(node, http.MethodGet) {
		return nil, nil
	}

	response, err := b.do(ctx, http.MethodGet, node.Backend, "", nil)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	// A backend may decline to list a directory it still accepts uploads for.
	if response.StatusCode == http.StatusMethodNotAllowed {
		return nil, nil
	}
	if err := responseError(response.StatusCode); err != nil {
		return nil, err
	}

	contentType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || contentType != directoryContentType {
		return nil, vfs.ErrFailure
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxListingBytes))
	decoder.DisallowUnknownFields()
	var listing struct {
		Children []config.Entry `json:"children"`
	}
	if err := decoder.Decode(&listing); err != nil {
		return nil, vfs.ErrFailure
	}
	if err := config.ValidateEntries(listing.Children); err != nil {
		return nil, vfs.ErrFailure
	}
	return listing.Children, nil
}

func (b *Backend) Open(ctx context.Context, node vfs.Node) (vfs.ReaderAtCloser, error) {
	if !permits(node, http.MethodGet) {
		return nil, vfs.ErrPermission
	}
	return &rangeReader{ctx: ctx, backend: b, url: node.Backend}, nil
}

func (b *Backend) Create(ctx context.Context, node vfs.Node) (vfs.WriterAtCloser, error) {
	if !permits(node, http.MethodPost) {
		return nil, vfs.ErrPermission
	}
	return vfs.NewStagedWriter(b.stagingDir, func(contents io.Reader) error {
		return b.mutate(ctx, http.MethodPost, node.Backend, uploadContentType, contents)
	})
}

func (b *Backend) Mkdir(ctx context.Context, node vfs.Node) error {
	if !permits(node, http.MethodPost) {
		return vfs.ErrPermission
	}
	return b.mutate(ctx, http.MethodPost, node.Backend, directoryEntryContentType, nil)
}

func (b *Backend) Remove(ctx context.Context, node vfs.Node) error {
	if !permits(node, http.MethodDelete) {
		return vfs.ErrPermission
	}
	return b.mutate(ctx, http.MethodDelete, node.Backend, "", nil)
}

// Rename is one DELETE on the source carrying where it should end up, so the
// source's own methods are the whole decision. What the destination is, or
// whether it can be reached at all, is the backend's answer to give.
func (b *Backend) Rename(ctx context.Context, node vfs.Node, target string) error {
	if !permits(node, http.MethodDelete) {
		return vfs.ErrPermission
	}
	parsed, err := url.Parse(node.Backend)
	if err != nil {
		return vfs.ErrFailure
	}
	parsed.RawQuery = url.Values{"renameTo": []string{target}}.Encode()
	return b.mutate(ctx, http.MethodDelete, parsed.String(), "", nil)
}

// Child names a member of a directory by appending one path segment to it.
//
// The child carries the directory's allowed_methods because a node that does
// not exist yet has none of its own, and creating within a directory is
// governed by that directory's POST. Nothing else is inherited: once the node
// exists, a listing states its methods and only those apply.
func (b *Backend) Child(node vfs.Node, name string) (vfs.Node, error) {
	parsed, err := url.Parse(node.Backend)
	if err != nil {
		return vfs.Node{}, vfs.ErrFailure
	}
	parsed.Path = strings.TrimSuffix(parsed.Path, "/") + "/" + name
	return vfs.Node{File: name, Backend: parsed.String(), AllowedMethods: node.AllowedMethods}, nil
}

func (b *Backend) mutate(ctx context.Context, method, rawURL, contentType string, body io.Reader) error {
	response, err := b.do(ctx, method, rawURL, contentType, body)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	return responseError(response.StatusCode)
}

func (b *Backend) do(ctx context.Context, method, rawURL, contentType string, body io.Reader) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, vfs.ErrFailure
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}

	client := *b.client
	client.CheckRedirect = sameBackendRedirect(request.URL)
	response, err := client.Do(request)
	if err != nil {
		return nil, vfs.ErrFailure
	}
	return response, nil
}

func sameBackendRedirect(origin *url.URL) func(*http.Request, []*http.Request) error {
	return func(request *http.Request, _ []*http.Request) error {
		if request.URL.Scheme != origin.Scheme || request.URL.Host != origin.Host || !pathHasPrefix(request.URL.Path, origin.Path) {
			return errors.New("redirect outside configured backend")
		}
		return nil
	}
}

func pathHasPrefix(candidate, prefix string) bool {
	prefix = strings.TrimSuffix(prefix, "/")
	return candidate == prefix || strings.HasPrefix(candidate, prefix+"/")
}

// permits reports whether the proxy may send method to this node. An empty
// list states nothing and so forbids nothing. It applies to the node that
// carries it and is never inherited from or by another.
func permits(node vfs.Node, method string) bool {
	if len(node.AllowedMethods) == 0 {
		return true
	}
	for _, allowed := range node.AllowedMethods {
		if allowed == method {
			return true
		}
	}
	return false
}

// responseError translates a status into the outcome a caller may see. Nothing
// of the response itself travels with it.
func responseError(status int) error {
	switch {
	case status >= http.StatusOK && status < http.StatusMultipleChoices:
		return nil
	case status == http.StatusUnauthorized, status == http.StatusForbidden:
		return vfs.ErrPermission
	case status == http.StatusNotFound:
		return vfs.ErrNotExist
	case status == http.StatusMethodNotAllowed:
		return vfs.ErrUnsupported
	default:
		return vfs.ErrFailure
	}
}

// rangeReader reads a file with RFC 9110 Range requests.
//
// A backend that honours them is read a window at a time. One that answers a
// range request with the whole file leaves no way to seek within the response,
// so the body is staged on disk once and every later read is served from there.
type rangeReader struct {
	ctx     context.Context
	backend *Backend
	url     string

	mu     sync.Mutex
	staged *vfs.StagingFile
}

func (r *rangeReader) ReadAt(destination []byte, offset int64) (int, error) {
	if len(destination) == 0 {
		return 0, nil
	}
	// Only the staged file is shared state. Requests are deliberately made
	// without the lock held, since a client reading a large file keeps several
	// in flight at once.
	if staged := r.stagedFile(); staged != nil {
		return staged.ReadAt(destination, offset)
	}

	response, err := r.request(offset, len(destination))
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()

	switch response.StatusCode {
	case http.StatusRequestedRangeNotSatisfiable:
		// A client reading to the end asks one range past it.
		return 0, io.EOF
	case http.StatusPartialContent:
		count, err := io.ReadFull(response.Body, destination)
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return count, io.EOF
		}
		return count, err
	case http.StatusOK:
		staged, err := r.stage(response.Body)
		if err != nil {
			return 0, err
		}
		return staged.ReadAt(destination, offset)
	default:
		if err := responseError(response.StatusCode); err != nil {
			return 0, err
		}
		return 0, vfs.ErrFailure
	}
}

func (r *rangeReader) request(offset int64, length int) (*http.Response, error) {
	request, err := http.NewRequestWithContext(r.ctx, http.MethodGet, r.url, nil)
	if err != nil {
		return nil, vfs.ErrFailure
	}
	request.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", offset, offset+int64(length)-1))

	client := *r.backend.client
	client.CheckRedirect = sameBackendRedirect(request.URL)
	response, err := client.Do(request)
	if err != nil {
		return nil, vfs.ErrFailure
	}
	return response, nil
}

func (r *rangeReader) stagedFile() *vfs.StagingFile {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.staged
}

// stage copies a whole-file response to disk and adopts it. A concurrent read
// may have staged the same body first, in which case theirs is kept and ours
// is discarded — either copy is the same file.
func (r *rangeReader) stage(body io.Reader) (*vfs.StagingFile, error) {
	staged, err := vfs.NewStagingFile(r.backend.stagingDir, "download-*")
	if err != nil {
		return nil, vfs.ErrFailure
	}
	if _, err := io.Copy(staged, body); err != nil {
		_ = staged.Close()
		return nil, vfs.ErrFailure
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.staged != nil {
		_ = staged.Close()
		return r.staged, nil
	}
	r.staged = staged
	return staged, nil
}

func (r *rangeReader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.staged == nil {
		return nil
	}
	err := r.staged.Close()
	r.staged = nil
	return err
}

var _ vfs.Backend = (*Backend)(nil)
