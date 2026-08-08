// Package localfs serves virtual filesystem nodes from directories on this
// host, named by file:// URLs.
//
// A deployment states which directories may be served and nothing outside them
// is reachable. Each one is held open as an os.Root, and every operation names
// its target relative to that root, so confinement is the kernel's answer
// rather than this package's: a name cannot climb out with .., a symlink cannot
// point out, and the check is not separable from the operation it guards. The
// only path arithmetic here is deciding which root a URL belongs to.
package localfs

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"sftp-proxy/internal/config"
	"sftp-proxy/internal/vfs"
)

// Modes for what this backend creates, as touch and mkdir use, so an uploaded
// file lands with the mode anything else on the host would give it. The process
// umask is what narrows them.
const (
	createFileMode      fs.FileMode = 0666
	createDirectoryMode fs.FileMode = 0777
)

// allBits is every permission bit: the mask a node that states none imposes,
// which is to say none at all.
const allBits fs.FileMode = 0777

type Backend struct {
	roots []*os.Root
}

// New opens each allowed prefix. A prefix that is missing, is not a directory,
// or cannot be opened is a startup failure rather than a directory that quietly
// serves nothing.
func New(allowedPrefixes []string) (*Backend, error) {
	if len(allowedPrefixes) == 0 {
		return nil, errors.New("at least one allowed prefix is required")
	}
	backend := &Backend{}
	for _, prefix := range allowedPrefixes {
		if !filepath.IsAbs(prefix) {
			_ = backend.Close()
			return nil, fmt.Errorf("allowed prefix %q must be absolute", prefix)
		}
		root, err := os.OpenRoot(filepath.Clean(prefix))
		if err != nil {
			_ = backend.Close()
			return nil, fmt.Errorf("open allowed prefix %q: %w", prefix, err)
		}
		backend.roots = append(backend.roots, root)
	}
	return backend, nil
}

func (b *Backend) Close() error {
	var err error
	for _, root := range b.roots {
		err = errors.Join(err, root.Close())
	}
	b.roots = nil
	return err
}

// location is where a node is: the root serving it, its path within that root
// and on the host, and the permissions the node's mask allows there.
type location struct {
	root   *os.Root
	rel    string
	target string
	mask   fs.FileMode
}

// childURL names a member of this location. A name is a name whatever
// characters it contains, so it is escaped into the URL rather than pasted in.
func (l location) childURL(name string) string {
	return (&url.URL{Scheme: config.FileScheme, Path: filepath.Join(l.target, name)}).String()
}

// resolve finds the root serving a node and the node's path within it.
//
// Choosing the root is the whole of the path work here. Everything after it
// names rel to that root, which is what makes a name that climbs out or a
// symlink pointing elsewhere the kernel's refusal rather than a check this
// package could forget to make.
func (b *Backend) resolve(node vfs.Node) (location, error) {
	target, ok := config.LocalPath(node.Backend)
	if !ok {
		return location{}, vfs.ErrFailure
	}
	for _, root := range b.roots {
		// Name is the cleaned absolute prefix New opened.
		if relative, inside := config.Relative(root.Name(), target); inside {
			return location{root: root, rel: relative, target: target, mask: mask(node)}, nil
		}
	}
	return location{}, vfs.ErrPermission
}

// mask is what a node's permissions allow. It can only take away: the mode the
// filesystem reports is narrowed by it, so the filesystem stays the outer bound
// on what may happen and this the inner one. A node stating no permissions
// imposes no mask of its own.
//
// A listing narrows each child by the mask in force on its directory and states
// the result, so a directory's mask bounds everything beneath it and a
// read-only directory yields a read-only tree.
func mask(node vfs.Node) fs.FileMode {
	if node.Permissions == nil {
		return allBits
	}
	return fs.FileMode(*node.Permissions) & allBits
}

// readable and writable ask what a mode permits. Any read bit permits reading
// and listing and any write bit permits every change, because the proxy is one
// actor rather than an owner, a group, and everyone else.
func readable(mode fs.FileMode) bool { return mode&0444 != 0 }
func writable(mode fs.FileMode) bool { return mode&0222 != 0 }

func (b *Backend) List(ctx context.Context, node vfs.Node) ([]vfs.Node, error) {
	at, err := b.resolve(node)
	if err != nil {
		return nil, err
	}
	// A directory whose mask withholds reading is presented as empty, as an HTTP
	// directory refusing GET is: it may still be a place to write to.
	if !readable(at.mask) {
		return nil, nil
	}

	directory, err := at.root.Open(at.rel)
	if err != nil {
		return nil, outcome(ctx, err)
	}
	defer directory.Close()
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return nil, outcome(ctx, err)
	}

	children := make([]vfs.Node, 0, len(entries))
	for _, entry := range entries {
		if child, ok := at.child(entry); ok {
			children = append(children, child)
		}
	}
	// A directory is stored in whatever order it happens to be in. Sorting is
	// what makes two listings of an unchanged directory the same listing.
	slices.SortFunc(children, func(left, right vfs.Node) int {
		return strings.Compare(left.Name(), right.Name())
	})
	return children, nil
}

// child describes one member of a directory. Anything that is not a plain file
// or directory is left out, a symlink included, since links are not modelled;
// so is a name no client could ask for, and an upload still in progress.
func (l location) child(entry os.DirEntry) (vfs.Node, bool) {
	name := entry.Name()
	if !entry.Type().IsRegular() && !entry.IsDir() {
		return vfs.Node{}, false
	}
	if !config.ValidName(name) || strings.HasPrefix(name, uploadPrefix) {
		return vfs.Node{}, false
	}
	info, err := entry.Info()
	if err != nil {
		return vfs.Node{}, false
	}

	permissions := uint32(info.Mode().Perm() & l.mask)
	modified := info.ModTime()
	child := vfs.Node{
		Backend:     l.childURL(name),
		Permissions: &permissions,
		Mtime:       &modified,
	}
	if entry.IsDir() {
		child.Directory = name
	} else {
		child.File = name
		child.Size = info.Size()
	}
	return child, true
}

func (b *Backend) Open(ctx context.Context, node vfs.Node) (vfs.ReaderAtCloser, error) {
	at, err := b.resolve(node)
	if err != nil {
		return nil, err
	}
	if !readable(at.mask) {
		return nil, vfs.ErrPermission
	}

	file, err := at.root.Open(at.rel)
	if err != nil {
		return nil, outcome(ctx, err)
	}
	// The file that was opened is the one asked about, so what it reports cannot
	// have been swapped for something else between the two.
	info, err := file.Stat()
	switch {
	case err != nil:
		_ = file.Close()
		return nil, outcome(ctx, err)
	case !info.Mode().IsRegular():
		_ = file.Close()
		return nil, vfs.ErrUnsupported
	case !readable(info.Mode().Perm() & at.mask):
		_ = file.Close()
		return nil, vfs.ErrPermission
	}
	return localFile{ctx: ctx, file: file}, nil
}

func (b *Backend) Create(ctx context.Context, node vfs.Node) (vfs.WriterAtCloser, error) {
	at, err := b.resolve(node)
	if err != nil {
		return nil, err
	}
	if !writable(at.mask) {
		return nil, vfs.ErrPermission
	}
	// A file already there states its own permissions. One that does not exist
	// yet has none, and the mask it inherited from its directory is all there is
	// to ask.
	switch info, err := at.root.Stat(at.rel); {
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return nil, outcome(ctx, err)
	case err == nil && info.IsDir():
		return nil, vfs.ErrUnsupported
	case err == nil && !writable(info.Mode().Perm()&at.mask):
		return nil, vfs.ErrPermission
	}
	return newUpload(ctx, at)
}

func (b *Backend) Mkdir(ctx context.Context, node vfs.Node) error {
	at, err := b.resolve(node)
	if err != nil {
		return err
	}
	if !writable(at.mask) {
		return vfs.ErrPermission
	}
	return outcome(ctx, at.root.Mkdir(at.rel, createDirectoryMode))
}

// Remove deletes a file or an empty directory, whichever the node is.
func (b *Backend) Remove(ctx context.Context, node vfs.Node) error {
	at, err := b.resolve(node)
	if err != nil {
		return err
	}
	if err := at.permitChange(ctx); err != nil {
		return err
	}
	return outcome(ctx, at.root.Remove(at.rel))
}

// Rename moves a node within the directory it is already in. Where a virtual
// path leads is the filesystem's knowledge rather than a backend's, so a
// destination anywhere else is refused rather than guessed at.
func (b *Backend) Rename(ctx context.Context, node vfs.Node, from, to string) error {
	if path.Dir(from) != path.Dir(to) {
		return vfs.ErrUnsupported
	}
	name := path.Base(to)
	if !config.ValidName(name) {
		return vfs.ErrFailure
	}
	at, err := b.resolve(node)
	if err != nil {
		return err
	}
	if err := at.permitChange(ctx); err != nil {
		return err
	}
	// Rename replaces whatever is at the destination, and SFTP says a rename
	// that would do so is an error rather than a replacement.
	//
	// TOCTOU is possible but hard to avoid:
	// - Renameat2 is linux only
	// - Rename already protects on windows
	// - and Renameexnp is mac only
	target := filepath.Join(filepath.Dir(at.rel), name)
	switch _, err := at.root.Stat(target); {
	case err == nil:
		return vfs.ErrExist
	case !errors.Is(err, fs.ErrNotExist):
		return outcome(ctx, err)
	}
	return outcome(ctx, at.root.Rename(at.rel, target))
}

// Child names a member of a directory, whether or not it exists yet, by
// appending one escaped segment to the directory's URL. It carries the mask in
// force on the directory and its upload limit, because a node that does not
// exist has neither of its own.
func (b *Backend) Child(node vfs.Node, name string) (vfs.Node, error) {
	at, err := b.resolve(node)
	if err != nil {
		return vfs.Node{}, err
	}
	permissions := uint32(at.mask)
	return vfs.Node{
		File:          name,
		Backend:       at.childURL(name),
		Permissions:   &permissions,
		MaxUploadSize: node.MaxUploadSize,
	}, nil
}

// permitChange reports whether an existing node may be altered: both the mask
// in force and the mode the filesystem reports must allow writing.
func (l location) permitChange(ctx context.Context) error {
	if !writable(l.mask) {
		return vfs.ErrPermission
	}
	info, err := l.root.Stat(l.rel)
	if err != nil {
		return outcome(ctx, err)
	}
	if !writable(info.Mode().Perm() & l.mask) {
		return vfs.ErrPermission
	}
	return nil
}

var _ vfs.Backend = (*Backend)(nil)
