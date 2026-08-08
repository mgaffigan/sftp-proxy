// Package httpfs serves virtual filesystem nodes over the HTTP backend
// contract: GET lists a directory or reads a file, POST creates, DELETE
// removes, and DELETE with a renameTo query moves.
package httpfs

import (
	"context"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"sftp-proxy/internal/config"
	"sftp-proxy/internal/headers"
	"sftp-proxy/internal/telemetry"
	"sftp-proxy/internal/vfs"
)

const directoryContentType = "application/vnd.sftpproxy.directory+json"
const directoryEntryContentType = "application/vnd.sftpproxy.directoryentry"
const uploadContentType = "application/octet-stream"

// maxListingBytes bounds a directory listing response.
const maxListingBytes = 8 << 20

type Backend struct {
	client     *http.Client
	stagingDir string
}

func New(client *http.Client, stagingDir string) *Backend {
	return &Backend{client: telemetry.NewHTTPClient(client), stagingDir: stagingDir}
}

func (b *Backend) List(ctx context.Context, node vfs.Node) ([]vfs.Node, error) {
	// A directory that does not permit GET is presented as empty rather than
	// asked about, which is the point of declaring allowedMethods: it keeps
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
	return &openFile{origin: &origin{
		ctx:        ctx,
		client:     b.client,
		url:        node.Backend,
		stagingDir: b.stagingDir,
	}}, nil
}

func (b *Backend) Create(ctx context.Context, node vfs.Node) (vfs.WriterAtCloser, error) {
	if !permits(node, http.MethodPost) {
		return nil, vfs.ErrPermission
	}
	return vfs.NewStagedWriter(b.stagingDir, func(contents *vfs.StagingFile) error {
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
func (b *Backend) Rename(ctx context.Context, node vfs.Node, _, target string) error {
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
// The child carries the directory's allowedMethods and maxUploadSize because a
// node that does not exist yet has none of its own. Once the node exists, a
// listing states its properties and only those apply.
func (b *Backend) Child(node vfs.Node, name string) (vfs.Node, error) {
	parsed, err := url.Parse(node.Backend)
	if err != nil {
		return vfs.Node{}, vfs.ErrFailure
	}
	parsed.Path = strings.TrimSuffix(parsed.Path, "/") + "/" + name
	return vfs.Node{
		File:           name,
		Backend:        parsed.String(),
		AllowedMethods: node.AllowedMethods,
		MaxUploadSize:  node.MaxUploadSize,
	}, nil
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
	request, err := http.NewRequest(method, rawURL, body)
	if err != nil {
		return nil, vfs.ErrFailure
	}
	stamp(ctx, request)
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}

	response, err := b.client.Do(request.WithContext(ctx))
	if err != nil {
		return nil, vfs.ErrFailure
	}
	return response, nil
}

// propagate headers from the context into the HTTP request.
func stamp(ctx context.Context, request *http.Request) {
	for name, value := range headers.From(ctx) {
		request.Header.Set(name, value)
	}
}

// permits reports whether the proxy may send method to this node. An empty
// list states nothing and so forbids nothing. It applies to the node that
// carries it and is never inherited from or by another.
func permits(node vfs.Node, method string) bool {
	if len(node.AllowedMethods) == 0 {
		return true
	}
	return slices.Contains(node.AllowedMethods, method)
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

var _ vfs.Backend = (*Backend)(nil)
