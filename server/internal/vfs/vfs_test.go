package vfs

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"sftp-proxy/internal/config"
)

// mock is a Backend that serves a fixed tree and records every call, so a test
// can assert not only what was resolved but how much work resolving it cost.
type mock struct {
	scheme   string
	children map[string][]Node
	fail     error
	writer   WriterAtCloser

	mu    sync.Mutex
	calls []string
}

func newMock(scheme string) *mock {
	return &mock{scheme: scheme, children: map[string][]Node{}}
}

// dir adds a directory at url holding the named children. A name ending in "/"
// is itself a directory.
func (m *mock) dir(url string, names ...string) *mock {
	nodes := make([]Node, 0, len(names))
	for _, name := range names {
		if trimmed, isDir := strings.CutSuffix(name, "/"); isDir {
			nodes = append(nodes, Node{Directory: trimmed, Backend: url + "/" + trimmed})
		} else {
			nodes = append(nodes, Node{File: name, Backend: url + "/" + name, Size: int64(len(name))})
		}
	}
	m.children[url] = nodes
	return m
}

func (m *mock) record(format string, args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, fmt.Sprintf(format, args...))
}

func (m *mock) log() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.calls...)
}

// count matches a call exactly; countKind matches every call of one kind.
func (m *mock) count(call string) int {
	total := 0
	for _, logged := range m.log() {
		if logged == call {
			total++
		}
	}
	return total
}

func (m *mock) countKind(kind string) int {
	total := 0
	for _, logged := range m.log() {
		if strings.HasPrefix(logged, kind+" ") {
			total++
		}
	}
	return total
}

func (m *mock) reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = nil
}

func (m *mock) List(ctx context.Context, node Node) ([]Node, error) {
	m.record("List %s", node.Backend)
	if m.fail != nil {
		return nil, m.fail
	}
	return m.children[node.Backend], nil
}

func (m *mock) Open(ctx context.Context, node Node) (ReaderAtCloser, error) {
	m.record("Open %s", node.Backend)
	return nil, m.fail
}

func (m *mock) Create(ctx context.Context, node Node) (WriterAtCloser, error) {
	m.record("Create %s", node.Backend)
	if m.fail != nil {
		return nil, m.fail
	}
	return m.writer, nil
}

func (m *mock) Mkdir(ctx context.Context, node Node) error {
	m.record("Mkdir %s", node.Backend)
	return m.fail
}

func (m *mock) Remove(ctx context.Context, node Node) error {
	m.record("Remove %s", node.Backend)
	return m.fail
}

func (m *mock) Rename(ctx context.Context, node Node, target string) error {
	m.record("Rename %s -> %s", node.Backend, target)
	return m.fail
}

func (m *mock) Child(node Node, name string) (Node, error) {
	m.record("Child %s %s", node.Backend, name)
	return Node{File: name, Backend: node.Backend + "/" + name, MaxUploadSize: node.MaxUploadSize}, nil
}

// tree is the fixture used throughout: /a/b/c.txt, all served by one backend.
func tree(t *testing.T) (*FS, *mock) {
	t.Helper()
	backend := newMock("mock")
	backend.dir("mock://root", "a/").
		dir("mock://root/a", "b/").
		dir("mock://root/a/b", "c.txt")
	return New(config.RootFS{Backend: "mock://root"}, Backends{"mock": backend}), backend
}

func TestResolveWalksOnceAndReusesTheResult(t *testing.T) {
	filesystem, backend := tree(t)
	ctx := context.Background()

	if _, err := filesystem.Open(ctx, "/a/b/c.txt"); err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if got := backend.countKind("List"); got != 3 {
		t.Fatalf("listings on a cold walk = %d, want 3 (root, a, b): %v", got, backend.log())
	}

	backend.reset()
	if _, err := filesystem.Open(ctx, "/a/b/c.txt"); err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if got := backend.countKind("List"); got != 0 {
		t.Fatalf("listings on a warm walk = %d, want 0: %v", got, backend.log())
	}
	if got := backend.count("Open mock://root/a/b/c.txt"); got != 1 {
		t.Fatalf("opened %d times at the right URL, want 1: %v", got, backend.log())
	}
}

func TestListAlwaysAsksTheBackend(t *testing.T) {
	filesystem, backend := tree(t)
	ctx := context.Background()

	for range 2 {
		if _, err := filesystem.List(ctx, "/a/b"); err != nil {
			t.Fatalf("List() error = %v", err)
		}
	}
	// Twice for /a/b itself: a listing is never answered from memory. Once for
	// root and once for /a, whose locations are remembered after the first walk.
	if got := backend.count("List mock://root/a/b"); got != 2 {
		t.Fatalf("listings of /a/b = %d, want 2: %v", got, backend.log())
	}
	if got := backend.count("List mock://root"); got != 1 {
		t.Fatalf("listings of root = %d, want 1: %v", got, backend.log())
	}
}

func TestStatIsNeverAnsweredFromCache(t *testing.T) {
	filesystem, backend := tree(t)
	ctx := context.Background()

	node, err := filesystem.Stat(ctx, "/a/b/c.txt")
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if node.Name() != "c.txt" || node.Size != int64(len("c.txt")) {
		t.Fatalf("Stat() = %+v", node)
	}

	// A second stat re-reads the containing listing, since size and kind must
	// be current, but no longer walks the ancestors above it.
	backend.reset()
	if _, err := filesystem.Stat(ctx, "/a/b/c.txt"); err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if got := backend.log(); len(got) != 1 || got[0] != "List mock://root/a/b" {
		t.Fatalf("second stat did %v, want one listing of /a/b", got)
	}
}

func TestStatOfRootNeedsNoBackend(t *testing.T) {
	filesystem, backend := tree(t)
	node, err := filesystem.Stat(context.Background(), "/")
	if err != nil {
		t.Fatalf("Stat(/) error = %v", err)
	}
	if !node.IsDirectory() || len(backend.log()) != 0 {
		t.Fatalf("Stat(/) = %+v after %v", node, backend.log())
	}
}

func TestListingMaySendAChildToAnotherBackend(t *testing.T) {
	primary := newMock("mock")
	other := newMock("other")
	// The primary's listing hands back a directory served by a different scheme.
	primary.children["mock://root"] = []Node{{Directory: "shared", Backend: "other://bucket"}}
	other.dir("other://bucket", "far.txt")

	filesystem := New(config.RootFS{Backend: "mock://root"},
		Backends{"mock": primary, "other": other})

	children, err := filesystem.List(context.Background(), "/shared")
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(children) != 1 || children[0].Name() != "far.txt" {
		t.Fatalf("children = %+v", children)
	}
	if other.count("List other://bucket") != 1 {
		t.Fatalf("the other backend was not consulted: %v", other.log())
	}
	if primary.count("List other://bucket") != 0 {
		t.Fatalf("the primary served a foreign scheme: %v", primary.log())
	}
}

func TestUnregisteredSchemeIsUnreachable(t *testing.T) {
	primary := newMock("mock")
	primary.children["mock://root"] = []Node{{Directory: "local", Backend: "file:///etc"}}
	filesystem := New(config.RootFS{Backend: "mock://root"}, Backends{"mock": primary})

	// A backend the deployment did not register cannot be reached, however the
	// entry naming it arrived.
	if _, err := filesystem.List(context.Background(), "/local"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("List() error = %v, want unsupported", err)
	}
}

func TestStaticSubtreeIsServedWithoutABackend(t *testing.T) {
	backend := newMock("mock")
	backend.dir("mock://remote", "far.txt")
	root := config.RootFS{Children: []config.Entry{
		{Directory: "static", Children: []config.Entry{{File: "near.txt", Backend: "mock://remote/near.txt"}}},
		{Directory: "remote", Backend: "mock://remote"},
	}}
	filesystem := New(root, Backends{"mock": backend})
	ctx := context.Background()

	children, err := filesystem.List(ctx, "/static")
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(children) != 1 || children[0].Name() != "near.txt" {
		t.Fatalf("children = %+v", children)
	}
	if len(backend.log()) != 0 {
		t.Fatalf("a static subtree reached a backend: %v", backend.log())
	}

	// The static tree and a backend-served one coexist under the same root.
	if _, err := filesystem.List(ctx, "/remote"); err != nil {
		t.Fatalf("List(/remote) error = %v", err)
	}
}

func TestRemoveForgetsThePathItRemoved(t *testing.T) {
	filesystem, backend := tree(t)
	ctx := context.Background()

	if _, err := filesystem.Stat(ctx, "/a/b/c.txt"); err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if err := filesystem.Remove(ctx, "/a/b/c.txt"); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	if backend.count("Remove mock://root/a/b/c.txt") != 1 {
		t.Fatalf("removed the wrong node: %v", backend.log())
	}

	// Gone from the fixture, and gone from the cache: resolving it again must
	// consult the backend rather than hand back where it used to be.
	delete(backend.children, "mock://root/a/b")
	backend.dir("mock://root/a/b")
	if _, err := filesystem.Open(ctx, "/a/b/c.txt"); !errors.Is(err, ErrNotExist) {
		t.Fatalf("Open() after remove = %v, want no such file", err)
	}
}

func TestRenameForgetsTheWholeSubtreeItMoved(t *testing.T) {
	filesystem, backend := tree(t)
	ctx := context.Background()

	if _, err := filesystem.Open(ctx, "/a/b/c.txt"); err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if err := filesystem.Rename(ctx, "/a/b", "/a/moved"); err != nil {
		t.Fatalf("Rename() error = %v", err)
	}
	if got := backend.count("Rename mock://root/a/b -> /a/moved"); got != 1 {
		t.Fatalf("rename call = %v", backend.log())
	}

	// /a/b/c.txt moved with its directory, so the cached descendant must not
	// survive to answer for it.
	backend.dir("mock://root/a", "moved/")
	delete(backend.children, "mock://root/a/b")
	backend.reset()
	if _, err := filesystem.Open(ctx, "/a/b/c.txt"); !errors.Is(err, ErrNotExist) {
		t.Fatalf("Open() after rename = %v, want no such file", err)
	}
	if backend.countKind("List") == 0 {
		t.Fatal("the moved descendant was answered from cache")
	}
}

func TestRejectsPathsThatAreNotAbsoluteAndClean(t *testing.T) {
	filesystem, backend := tree(t)
	ctx := context.Background()

	for _, path := range []string{"relative.txt", "/a/../escape", "/a/./b", "/a//b", "/a/\x00b"} {
		if _, err := filesystem.Stat(ctx, path); !errors.Is(err, ErrNotExist) {
			t.Errorf("Stat(%q) error = %v, want no such file", path, err)
		}
	}
	if len(backend.log()) != 0 {
		t.Fatalf("an invalid path reached a backend: %v", backend.log())
	}

	// A rename validates its destination too, before touching the source.
	if err := filesystem.Rename(ctx, "/a/b/c.txt", "/a/../escape"); !errors.Is(err, ErrNotExist) {
		t.Fatalf("Rename() to an invalid target = %v, want no such file", err)
	}
	if backend.countKind("Rename") != 0 {
		t.Fatalf("an invalid rename target reached the backend: %v", backend.log())
	}
}

func TestCreateNamesANewChildButReusesAnExistingNode(t *testing.T) {
	filesystem, backend := tree(t)
	ctx := context.Background()

	// A path with no node of its own is named by its containing directory.
	if _, err := filesystem.Create(ctx, "/a/b/new.txt"); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if backend.count("Child mock://root/a/b new.txt") != 1 {
		t.Fatalf("new file was not named by its parent: %v", backend.log())
	}
	if backend.count("Create mock://root/a/b/new.txt") != 1 {
		t.Fatalf("created at the wrong URL: %v", backend.log())
	}

	// An existing file is written through its own location, which a listing is
	// free to put anywhere.
	backend.children["mock://root/a/b"] = []Node{{File: "c.txt", Backend: "mock://elsewhere/c.txt"}}
	backend.reset()
	if _, err := filesystem.Create(ctx, "/a/b/c.txt"); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if backend.count("Create mock://elsewhere/c.txt") != 1 {
		t.Fatalf("existing file was not written at its own URL: %v", backend.log())
	}
	if backend.countKind("Child") != 0 {
		t.Fatalf("existing file was renamed by its parent: %v", backend.log())
	}
}

func TestCreateAndMkdirRefuseAnExistingDirectory(t *testing.T) {
	filesystem, _ := tree(t)
	ctx := context.Background()

	if _, err := filesystem.Create(ctx, "/a/b"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Create() over a directory = %v, want unsupported", err)
	}
	if err := filesystem.Mkdir(ctx, "/a/b"); !errors.Is(err, ErrExist) {
		t.Fatalf("Mkdir() over a directory = %v, want exists", err)
	}
}

type recordingWriter struct {
	writes int
}

func (writer *recordingWriter) WriteAt(data []byte, offset int64) (int, error) {
	writer.writes++
	return len(data), nil
}

func (writer *recordingWriter) Close() error { return nil }
func (writer *recordingWriter) Abort() error { return nil }

func TestCreateEnforcesTheExactNodeUploadSize(t *testing.T) {
	backend := newMock("mock")
	writer := &recordingWriter{}
	backend.writer = writer
	filesystem := New(config.RootFS{Children: []config.Entry{
		{File: "limited.txt", Backend: "mock://files/limited.txt", MaxUploadSize: 3},
		{File: "unlimited.txt", Backend: "mock://files/unlimited.txt"},
	}}, Backends{"mock": backend})

	limited, err := filesystem.Create(context.Background(), "/limited.txt")
	if err != nil {
		t.Fatalf("Create(limited) error = %v", err)
	}
	if count, err := limited.WriteAt([]byte("abc"), 0); err != nil || count != 3 {
		t.Fatalf("limited WriteAt within limit = (%d, %v), want (3, nil)", count, err)
	}
	if count, err := limited.WriteAt([]byte("d"), 3); count != 0 || !errors.Is(err, ErrFailure) {
		t.Fatalf("limited WriteAt beyond limit = (%d, %v), want (0, failure)", count, err)
	}
	if writer.writes != 1 {
		t.Fatalf("backend writes after rejected upload = %d, want 1", writer.writes)
	}

	unlimited, err := filesystem.Create(context.Background(), "/unlimited.txt")
	if err != nil {
		t.Fatalf("Create(unlimited) error = %v", err)
	}
	if count, err := unlimited.WriteAt([]byte("abcd"), 0); err != nil || count != 4 {
		t.Fatalf("unlimited WriteAt = (%d, %v), want (4, nil)", count, err)
	}
}

func TestCreateEnforcesContainingDirectoryUploadSizeForNewFiles(t *testing.T) {
	backend := newMock("mock")
	writer := &recordingWriter{}
	backend.writer = writer
	filesystem := New(config.RootFS{Children: []config.Entry{{
		Directory:     "inbound",
		Backend:       "mock://files/inbound",
		MaxUploadSize: 3,
	}}}, Backends{"mock": backend})

	created, err := filesystem.Create(context.Background(), "/inbound/new.txt")
	if err != nil {
		t.Fatalf("Create(new) error = %v", err)
	}
	if count, err := created.WriteAt([]byte("abc"), 0); err != nil || count != 3 {
		t.Fatalf("new WriteAt within limit = (%d, %v), want (3, nil)", count, err)
	}
	if count, err := created.WriteAt([]byte("d"), 3); count != 0 || !errors.Is(err, ErrFailure) {
		t.Fatalf("new WriteAt beyond limit = (%d, %v), want (0, failure)", count, err)
	}
	if writer.writes != 1 {
		t.Fatalf("backend writes after rejected new-file upload = %d, want 1", writer.writes)
	}
}

func TestMkdirNamesTheDirectoryFromItsParent(t *testing.T) {
	filesystem, backend := tree(t)
	if err := filesystem.Mkdir(context.Background(), "/a/b/fresh"); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	if backend.count("Mkdir mock://root/a/b/fresh") != 1 {
		t.Fatalf("mkdir call = %v", backend.log())
	}
}

func TestDescendingThroughAFileFails(t *testing.T) {
	filesystem, _ := tree(t)
	if _, err := filesystem.Stat(context.Background(), "/a/b/c.txt/deeper"); !errors.Is(err, ErrNotExist) {
		t.Fatalf("Stat() below a file = %v, want no such file", err)
	}
}

func TestBackendFailuresPassThroughUntranslated(t *testing.T) {
	filesystem, backend := tree(t)
	backend.fail = ErrPermission
	if _, err := filesystem.List(context.Background(), "/a"); !errors.Is(err, ErrPermission) {
		t.Fatalf("List() error = %v, want permission denied", err)
	}
}

func TestConcurrentResolutionIsSafe(t *testing.T) {
	filesystem, _ := tree(t)
	ctx := context.Background()

	var group sync.WaitGroup
	for range 16 {
		group.Go(func() {
			if _, err := filesystem.Stat(ctx, "/a/b/c.txt"); err != nil {
				t.Errorf("Stat() error = %v", err)
			}
			if err := filesystem.Remove(ctx, "/a/b/c.txt"); err != nil {
				t.Errorf("Remove() error = %v", err)
			}
		})
	}
	group.Wait()
}
