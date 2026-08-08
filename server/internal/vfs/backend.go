package vfs

import (
	"context"
	"errors"
	"io"

	"sftp-proxy/internal/config"
)

// Node is one entry in the virtual filesystem. It is config.Entry itself, so
// the node shape is defined in exactly one place and nothing has to be
// converted to cross the backend boundary.
type Node = config.Entry

// Errors a backend reports. They describe the outcome, never the cause: a
// backend URL, a staging path, or a remote error string must not reach the
// caller, which passes these on to a client.
var (
	ErrNotExist    = errors.New("no such file or directory")
	ErrPermission  = errors.New("permission denied")
	ErrUnsupported = errors.New("operation not supported")
	ErrFailure     = errors.New("operation failed")
)

type ReaderAtCloser interface {
	io.ReaderAt
	io.Closer
}

type WriterAtCloser interface {
	io.WriterAt
	io.Closer
}

// Backend serves one storage protocol. The scheme of a node's backend URL
// selects it, so a directory listing may hand back children served by an
// entirely different backend.
//
// Every method takes the whole node rather than its URL, because what a backend
// may do with a node is the backend's own business: allowedMethods, for one,
// constrains HTTP traffic and is read only by the HTTP backend.
type Backend interface {
	List(ctx context.Context, node Node) ([]Node, error)
	Open(ctx context.Context, node Node) (ReaderAtCloser, error)
	Create(ctx context.Context, node Node) (WriterAtCloser, error)
	Mkdir(ctx context.Context, node Node) error
	Remove(ctx context.Context, node Node) error
	// Rename moves node to target, a cleaned root-relative virtual path. The
	// backend decides whether it can, including when target lies outside it.
	Rename(ctx context.Context, node Node, target string) error
	// Child names a member of a directory node, whether or not it exists yet,
	// so that a create has somewhere to write to. It copies any directory
	// policy that governs creation into the returned node.
	Child(node Node, name string) (Node, error)
}

// Backends maps a URL scheme to the backend serving it. The caller builds it,
// which is also how a deployment withholds one: a scheme with no entry here
// cannot be reached, whatever a config file or a backend listing asks for.
type Backends map[string]Backend
