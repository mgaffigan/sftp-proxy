// Package vfs presents one virtual filesystem assembled from a user's
// configured tree and whatever backends serve the nodes within it.
//
// It owns paths, traversal, and which backend serves what. It does not know
// how any storage protocol works, and it does not know it is being driven by
// SFTP.
package vfs

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"sync"

	"sftp-proxy/internal/config"
)

// ErrExist reports a node that already exists where a new one was asked for.
var ErrExist = errors.New("file already exists")

type FS struct {
	root     config.RootFS
	backends Backends

	mu       sync.Mutex
	resolved map[string]Node
}

type sizeLimitedWriter struct {
	WriterAtCloser
	maxSize int64
}

func (w sizeLimitedWriter) WriteAt(data []byte, offset int64) (int, error) {
	if offset < 0 || offset > w.maxSize || int64(len(data)) > w.maxSize-offset {
		return 0, ErrFailure
	}
	return w.WriterAtCloser.WriteAt(data, offset)
}

func New(root config.RootFS, backends Backends) *FS {
	return &FS{root: root, backends: backends, resolved: make(map[string]Node)}
}

// Stat reports the node at path. It never answers from the resolution cache:
// size and kind come from whichever listing describes the node right now.
func (f *FS) Stat(ctx context.Context, path string) (Node, error) {
	parts, err := splitPath(path)
	if err != nil {
		return Node{}, ErrNotExist
	}
	if len(parts) == 0 {
		return f.root.Entry(), nil
	}

	parent, err := f.resolve(ctx, parts[:len(parts)-1])
	if err != nil {
		return Node{}, err
	}
	children, err := f.list(ctx, parent)
	if err != nil {
		return Node{}, err
	}
	node, err := findChild(children, parts[len(parts)-1])
	if err != nil {
		return Node{}, err
	}
	f.remember(parts, node)
	return node, nil
}

// List reports the children of the directory at path, always by asking the
// backend. Listings are never cached.
func (f *FS) List(ctx context.Context, path string) ([]Node, error) {
	parts, err := splitPath(path)
	if err != nil {
		return nil, ErrNotExist
	}
	node, err := f.resolve(ctx, parts)
	if err != nil {
		return nil, err
	}
	if !node.IsDirectory() {
		return nil, ErrUnsupported
	}
	return f.list(ctx, node)
}

func (f *FS) Open(ctx context.Context, path string) (ReaderAtCloser, error) {
	parts, err := splitPath(path)
	if err != nil {
		return nil, ErrNotExist
	}
	node, err := f.resolve(ctx, parts)
	if err != nil {
		return nil, err
	}
	if node.IsDirectory() {
		return nil, ErrUnsupported
	}
	backend, err := f.backendFor(node)
	if err != nil {
		return nil, err
	}
	return backend.Open(ctx, node)
}

// Create opens the node at path for writing, creating it if it does not exist.
// An existing node is written through its own location rather than one derived
// from its parent, since a listing may place a child anywhere it likes.
func (f *FS) Create(ctx context.Context, path string) (WriterAtCloser, error) {
	parts, err := splitPath(path)
	if err != nil || len(parts) == 0 {
		return nil, ErrNotExist
	}

	node, err := f.resolve(ctx, parts)
	switch {
	case err == nil:
		if node.IsDirectory() {
			return nil, ErrUnsupported
		}
	case errors.Is(err, ErrNotExist):
		if node, err = f.newChild(ctx, parts); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}

	backend, err := f.backendFor(node)
	if err != nil {
		return nil, err
	}
	writer, err := backend.Create(ctx, node)
	if err != nil {
		return nil, err
	}
	if node.MaxUploadSize > 0 {
		return sizeLimitedWriter{WriterAtCloser: writer, maxSize: node.MaxUploadSize}, nil
	}
	return writer, nil
}

func (f *FS) Mkdir(ctx context.Context, path string) error {
	parts, err := splitPath(path)
	if err != nil || len(parts) == 0 {
		return ErrNotExist
	}
	if _, err := f.resolve(ctx, parts); err == nil {
		return ErrExist
	} else if !errors.Is(err, ErrNotExist) {
		return err
	}

	node, err := f.newChild(ctx, parts)
	if err != nil {
		return err
	}
	backend, err := f.backendFor(node)
	if err != nil {
		return err
	}
	return backend.Mkdir(ctx, node)
}

func (f *FS) Remove(ctx context.Context, path string) error {
	parts, err := splitPath(path)
	if err != nil || len(parts) == 0 {
		return ErrNotExist
	}
	node, err := f.resolve(ctx, parts)
	if err != nil {
		return err
	}
	backend, err := f.backendFor(node)
	if err != nil {
		return err
	}
	// Forget before acting: a failed remove costs only a re-resolution, while a
	// successful one left cached would hand out a location that is gone.
	f.forget(parts)
	return backend.Remove(ctx, node)
}

func (f *FS) Rename(ctx context.Context, from, to string) error {
	fromParts, err := splitPath(from)
	if err != nil || len(fromParts) == 0 {
		return ErrNotExist
	}
	toParts, err := splitPath(to)
	if err != nil || len(toParts) == 0 {
		return ErrNotExist
	}
	node, err := f.resolve(ctx, fromParts)
	if err != nil {
		return err
	}
	backend, err := f.backendFor(node)
	if err != nil {
		return err
	}
	// Both ends move: the source and everything beneath it stop being where
	// they were, and the destination stops being whatever it was before.
	f.forget(fromParts)
	f.forget(toParts)
	return backend.Rename(ctx, node, joinPath(toParts))
}

// newChild builds the node a create would bring into existence, by asking the
// containing directory's backend to name it.
func (f *FS) newChild(ctx context.Context, parts []string) (Node, error) {
	parent, err := f.resolve(ctx, parts[:len(parts)-1])
	if err != nil {
		return Node{}, err
	}
	if !parent.IsDirectory() {
		return Node{}, ErrNotExist
	}
	backend, err := f.backendFor(parent)
	if err != nil {
		return Node{}, err
	}
	return backend.Child(parent, parts[len(parts)-1])
}

// resolve walks parts to the node they name, resuming from the longest already
// resolved prefix. The cache answers where a path is, never what it contains,
// so every listing it walks through is fetched afresh.
func (f *FS) resolve(ctx context.Context, parts []string) (Node, error) {
	if len(parts) == 0 {
		return f.root.Entry(), nil
	}

	current, index := f.longestResolved(parts)
	for ; index < len(parts); index++ {
		if !current.IsDirectory() {
			return Node{}, ErrNotExist
		}
		children, err := f.list(ctx, current)
		if err != nil {
			return Node{}, err
		}
		if current, err = findChild(children, parts[index]); err != nil {
			return Node{}, err
		}
		f.remember(parts[:index+1], current)
	}
	return current, nil
}

// list returns a node's children, from its backend or, for a node that has
// none, from the tree the configuration laid out statically.
func (f *FS) list(ctx context.Context, node Node) ([]Node, error) {
	if node.Backend == "" {
		return node.Children, nil
	}
	backend, err := f.backendFor(node)
	if err != nil {
		return nil, err
	}
	return backend.List(ctx, node)
}

// backendFor selects the backend serving a node by its URL scheme. A scheme
// the caller did not register is unreachable, whether it arrived from a config
// file or from a backend's own listing.
func (f *FS) backendFor(node Node) (Backend, error) {
	if node.Backend == "" {
		return nil, ErrUnsupported
	}
	parsed, err := url.Parse(node.Backend)
	if err != nil || parsed.Scheme == "" {
		return nil, ErrFailure
	}
	backend, ok := f.backends[parsed.Scheme]
	if !ok {
		return nil, ErrUnsupported
	}
	return backend, nil
}

func (f *FS) longestResolved(parts []string) (Node, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for index := len(parts); index > 0; index-- {
		if node, ok := f.resolved[joinPath(parts[:index])]; ok {
			return node, index
		}
	}
	return f.root.Entry(), 0
}

func (f *FS) remember(parts []string, node Node) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resolved[joinPath(parts)] = node
}

// forget drops a path and everything beneath it. Renaming a directory relocates
// its whole subtree, so dropping the one path would leave descendants pointing
// at locations that no longer hold them.
func (f *FS) forget(parts []string) {
	path := joinPath(parts)
	prefix := path + "/"
	f.mu.Lock()
	defer f.mu.Unlock()
	for cached := range f.resolved {
		if cached == path || strings.HasPrefix(cached, prefix) {
			delete(f.resolved, cached)
		}
	}
}

// splitPath validates an absolute virtual path and returns its components. The
// root is no components rather than an error.
func splitPath(rawPath string) ([]string, error) {
	if rawPath == "" || rawPath == "/" {
		return nil, nil
	}
	if !strings.HasPrefix(rawPath, "/") {
		return nil, errors.New("path must be absolute")
	}
	parts := strings.Split(strings.TrimPrefix(rawPath, "/"), "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.ContainsRune(part, 0) {
			return nil, errors.New("invalid path")
		}
	}
	return parts, nil
}

func joinPath(parts []string) string {
	return "/" + strings.Join(parts, "/")
}

func findChild(children []Node, name string) (Node, error) {
	for _, child := range children {
		if child.Name() == name {
			return child, nil
		}
	}
	return Node{}, ErrNotExist
}
