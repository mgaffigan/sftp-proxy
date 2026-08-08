package localfs

import (
	"context"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sftp-proxy/internal/config"
	"sftp-proxy/internal/vfs"
)

// serve opens a backend over prefixes, the first of which is the one the tests
// mostly work in.
func serve(t *testing.T, prefixes ...string) *Backend {
	t.Helper()
	backend, err := New(prefixes)
	if err != nil {
		t.Fatalf("New(%v) error = %v", prefixes, err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	return backend
}

func fileURL(path string) string {
	return (&url.URL{Scheme: "file", Path: path}).String()
}

func dirNode(path string) vfs.Node {
	return vfs.Node{Directory: filepath.Base(path), Backend: fileURL(path)}
}

func fileNode(path string) vfs.Node {
	return vfs.Node{File: filepath.Base(path), Backend: fileURL(path)}
}

func masked(node vfs.Node, permissions uint32) vfs.Node {
	node.Permissions = &permissions
	return node
}

func write(t *testing.T, path, contents string, mode os.FileMode) string {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatal(err)
	}
	// WriteFile applies the umask to a file it creates, and these tests are
	// about the mode itself.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func names(children []vfs.Node) []string {
	found := make([]string, 0, len(children))
	for _, child := range children {
		found = append(found, child.Name())
	}
	return found
}

func TestNewRejectsWhatItCannotServe(t *testing.T) {
	regular := write(t, filepath.Join(t.TempDir(), "regular.txt"), "x", 0o644)

	for name, prefixes := range map[string][]string{
		"none":          nil,
		"relative":      {"srv/data"},
		"missing":       {filepath.Join(t.TempDir(), "absent")},
		"not directory": {regular},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New(prefixes); err == nil {
				t.Fatalf("New(%v) accepted it", prefixes)
			}
		})
	}
}

func TestRejectsBackendURLsThatNameNoLocalPath(t *testing.T) {
	root := t.TempDir()
	backend := serve(t, root)
	ctx := context.Background()

	for _, rawURL := range []string{
		"https://files.example.test/d",
		"mem://files/d",
		"file://elsewhere" + root,
		fileURL(root) + "?renameTo=%2Fx",
		"file:relative/path",
		"file://",
	} {
		_, err := backend.List(ctx, vfs.Node{Directory: "d", Backend: rawURL})
		if !errors.Is(err, vfs.ErrFailure) {
			t.Errorf("List(%q) error = %v, want failure", rawURL, err)
		}
	}
}

func TestServesOnlyWhatLiesBeneathAnAllowedPrefix(t *testing.T) {
	base := t.TempDir()
	allowed, sibling := filepath.Join(base, "data"), filepath.Join(base, "dataX")
	for _, directory := range []string{allowed, sibling} {
		if err := os.Mkdir(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write(t, filepath.Join(sibling, "secret.txt"), "not yours", 0o644)
	backend := serve(t, allowed)
	ctx := context.Background()

	if _, err := backend.List(ctx, dirNode(allowed)); err != nil {
		t.Fatalf("List() on the prefix itself error = %v", err)
	}

	// A sibling whose name merely starts with the prefix is a different
	// directory, and a path that climbs out and back in is still outside.
	for _, outside := range []string{
		sibling,
		filepath.Join(sibling, "secret.txt"),
		filepath.Join(allowed, "..", "dataX", "secret.txt"),
		"/etc",
	} {
		if _, err := backend.List(ctx, dirNode(outside)); !errors.Is(err, vfs.ErrPermission) {
			t.Errorf("List(%q) error = %v, want permission denied", outside, err)
		}
		if _, err := backend.Open(ctx, fileNode(outside)); !errors.Is(err, vfs.ErrPermission) {
			t.Errorf("Open(%q) error = %v, want permission denied", outside, err)
		}
	}
}

func TestSymlinksOutOfTheRootAreRefused(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	write(t, filepath.Join(outside, "secret.txt"), "not yours", 0o644)
	if err := os.Symlink(outside, filepath.Join(root, "absolute")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..", filepath.Base(outside)), filepath.Join(root, "relative")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(root, "secret.txt")); err != nil {
		t.Fatal(err)
	}
	backend := serve(t, root)
	ctx := context.Background()

	// A link is not a file or a directory, so it is not something a listing
	// offers a client in the first place.
	children, err := backend.List(ctx, dirNode(root))
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(children) != 0 {
		t.Fatalf("children = %v, want the links left out", names(children))
	}

	// Named directly, the link is refused where it is followed rather than
	// anywhere a check could have been forgotten.
	for _, escape := range []string{"absolute", "relative", "secret.txt"} {
		path := filepath.Join(root, escape)
		if _, err := backend.Open(ctx, fileNode(path)); err == nil {
			t.Errorf("Open(%q) followed a link out of the root", escape)
		}
		if _, err := backend.List(ctx, dirNode(filepath.Join(path, "secret.txt"))); err == nil {
			t.Errorf("List(%q) followed a link out of the root", escape)
		}
	}
}

func TestListDescribesOnlyPlainFilesAndDirectories(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "report.txt"), "hello", 0o640)
	if err := os.Mkdir(filepath.Join(root, "sub"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("report.txt", filepath.Join(root, "link.txt")); err != nil {
		t.Fatal(err)
	}
	// An upload in progress is nobody's business but the client making it.
	write(t, filepath.Join(root, uploadPrefix+"ABC"), "partial", 0o600)
	backend := serve(t, root)

	children, err := backend.List(context.Background(), dirNode(root))
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if got := names(children); strings.Join(got, ",") != "report.txt,sub" {
		t.Fatalf("children = %v", got)
	}

	report, sub := children[0], children[1]
	if report.IsDirectory() || report.Size != 5 || report.Mtime == nil {
		t.Errorf("file child = %+v", report)
	}
	if report.Permissions == nil || *report.Permissions != 0o640 {
		t.Errorf("file permissions = %v, want 0640", report.Permissions)
	}
	if !sub.IsDirectory() || sub.Permissions == nil || *sub.Permissions != 0o750 {
		t.Errorf("directory child = %+v", sub)
	}
	// Each child names itself, so nothing has to be reassembled to reach it.
	if _, err := backend.List(context.Background(), sub); err != nil {
		t.Errorf("List() of a listed child error = %v", err)
	}
}

func TestAMaskNarrowsPermissionsAndIsInherited(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "sub")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(nested, "report.txt"), "hello", 0o664)
	backend := serve(t, root)
	ctx := context.Background()

	// The mask takes the write bits away from everything it covers.
	children, err := backend.List(ctx, masked(dirNode(root), 0o555))
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(children) != 1 || *children[0].Permissions != 0o555 {
		t.Fatalf("children = %+v", children)
	}

	// The child was described by a masked listing, so what it states is already
	// narrowed, and listing it in turn narrows its own children the same way.
	grandchildren, err := backend.List(ctx, children[0])
	if err != nil {
		t.Fatalf("List() of the child error = %v", err)
	}
	if len(grandchildren) != 1 || *grandchildren[0].Permissions != 0o444 {
		t.Fatalf("grandchildren = %+v", grandchildren)
	}

	// And what it states is what is enforced.
	if _, err := backend.Create(ctx, grandchildren[0]); !errors.Is(err, vfs.ErrPermission) {
		t.Errorf("Create() in a read-only tree = %v, want permission denied", err)
	}
	if err := backend.Remove(ctx, grandchildren[0]); !errors.Is(err, vfs.ErrPermission) {
		t.Errorf("Remove() in a read-only tree = %v, want permission denied", err)
	}
	if _, err := backend.Open(ctx, grandchildren[0]); err != nil {
		t.Errorf("Open() in a read-only tree = %v, want it to be readable", err)
	}
}

func TestADirectoryWithNoReadBitListsEmptyAndStillTakesUploads(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "seed.txt"), "hello", 0o644)
	backend := serve(t, root)
	ctx := context.Background()
	dropOnly := masked(dirNode(root), 0o333)

	children, err := backend.List(ctx, dropOnly)
	if err != nil || len(children) != 0 {
		t.Fatalf("List() = (%v, %v), want (empty, nil)", names(children), err)
	}
	if _, err := backend.Open(ctx, masked(fileNode(filepath.Join(root, "seed.txt")), 0o333)); !errors.Is(err, vfs.ErrPermission) {
		t.Errorf("Open() error = %v, want permission denied", err)
	}

	child, err := backend.Child(dropOnly, "dropped.txt")
	if err != nil {
		t.Fatalf("Child() error = %v", err)
	}
	writer, err := backend.Create(ctx, child)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if _, err := writer.WriteAt([]byte("dropped"), 0); err != nil {
		t.Fatalf("WriteAt() error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if contents, err := os.ReadFile(filepath.Join(root, "dropped.txt")); err != nil || string(contents) != "dropped" {
		t.Fatalf("dropped.txt = (%q, %v)", contents, err)
	}
}

func TestOpenReadsAtOffsetsAndReportsTheSize(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "report.txt"), "hello world", 0o644)
	backend := serve(t, root)

	reader, err := backend.Open(context.Background(), fileNode(filepath.Join(root, "report.txt")))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer reader.Close()

	if size, err := reader.Size(); err != nil || size != 11 {
		t.Fatalf("Size() = (%d, %v), want 11", size, err)
	}
	window := make([]byte, 5)
	if count, err := reader.ReadAt(window, 6); err != nil || string(window[:count]) != "world" {
		t.Fatalf("ReadAt(6) = (%q, %v)", window[:count], err)
	}
	// A client reading to the end asks past it.
	if _, err := reader.ReadAt(window, 11); !errors.Is(err, io.EOF) {
		t.Fatalf("ReadAt(11) error = %v, want EOF", err)
	}
}

func TestOpenRefusesWhatIsNotAPlainFile(t *testing.T) {
	root := t.TempDir()
	backend := serve(t, root)

	if _, err := backend.Open(context.Background(), fileNode(root)); !errors.Is(err, vfs.ErrUnsupported) {
		t.Fatalf("Open() of a directory error = %v, want unsupported", err)
	}
}

func TestAnUploadIsPublishedWholeOrNotAtAll(t *testing.T) {
	root := t.TempDir()
	existing := write(t, filepath.Join(root, "report.txt"), "previous", 0o644)
	backend := serve(t, root)
	ctx := context.Background()

	writer, err := backend.Create(ctx, fileNode(existing))
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	// Written out of order, as an SFTP client may.
	if _, err := writer.WriteAt([]byte("world"), 6); err != nil {
		t.Fatalf("WriteAt() error = %v", err)
	}
	if _, err := writer.WriteAt([]byte("hello "), 0); err != nil {
		t.Fatalf("WriteAt() error = %v", err)
	}
	// Nothing has replaced the file that was there while the writes are in
	// flight, and no half-written name is offered to a client either.
	if contents, _ := os.ReadFile(existing); string(contents) != "previous" {
		t.Fatalf("report.txt = %q during the upload", contents)
	}
	children, err := backend.List(ctx, dirNode(root))
	if err != nil || len(children) != 1 {
		t.Fatalf("List() = (%v, %v), want only report.txt", names(children), err)
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if contents, err := os.ReadFile(existing); err != nil || string(contents) != "hello world" {
		t.Fatalf("report.txt = (%q, %v)", contents, err)
	}
	expectOnly(t, root, "report.txt")
}

func TestAnAbandonedUploadLeavesTheFileItWouldHaveReplaced(t *testing.T) {
	root := t.TempDir()
	existing := write(t, filepath.Join(root, "report.txt"), "previous", 0o644)
	backend := serve(t, root)

	writer, err := backend.Create(context.Background(), fileNode(existing))
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if _, err := writer.WriteAt([]byte("half"), 0); err != nil {
		t.Fatalf("WriteAt() error = %v", err)
	}
	if err := writer.Abort(); err != nil {
		t.Fatalf("Abort() error = %v", err)
	}
	if contents, err := os.ReadFile(existing); err != nil || string(contents) != "previous" {
		t.Fatalf("report.txt = (%q, %v), want it untouched", contents, err)
	}
	expectOnly(t, root, "report.txt")

	// An abort after the upload was published is not a second chance to undo it.
	if err := writer.Abort(); err != nil {
		t.Fatalf("second Abort() error = %v", err)
	}
	if _, err := writer.WriteAt([]byte("more"), 0); !errors.Is(err, vfs.ErrFailure) {
		t.Fatalf("WriteAt() after abort = %v, want failure", err)
	}
}

// expectOnly asserts what is left on disk, including the upload names a client
// never sees.
func expectOnly(t *testing.T, directory string, want ...string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	found := make([]string, 0, len(entries))
	for _, entry := range entries {
		found = append(found, entry.Name())
	}
	if strings.Join(found, ",") != strings.Join(want, ",") {
		t.Fatalf("%s contains %v, want %v", directory, found, want)
	}
}

func TestCreateRefusesAReadOnlyFileAndADirectory(t *testing.T) {
	root := t.TempDir()
	readOnly := write(t, filepath.Join(root, "read-only.txt"), "fixed", 0o444)
	backend := serve(t, root)
	ctx := context.Background()

	if _, err := backend.Create(ctx, fileNode(readOnly)); !errors.Is(err, vfs.ErrPermission) {
		t.Errorf("Create() over a read-only file = %v, want permission denied", err)
	}
	if _, err := backend.Create(ctx, fileNode(root)); !errors.Is(err, vfs.ErrUnsupported) {
		t.Errorf("Create() over a directory = %v, want unsupported", err)
	}
	expectOnly(t, root, "read-only.txt")
}

func TestMkdirAndRemove(t *testing.T) {
	root := t.TempDir()
	backend := serve(t, root)
	ctx := context.Background()

	created, err := backend.Child(dirNode(root), "Archive")
	if err != nil {
		t.Fatalf("Child() error = %v", err)
	}
	if err := backend.Mkdir(ctx, created); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	if info, err := os.Stat(filepath.Join(root, "Archive")); err != nil || !info.IsDir() {
		t.Fatalf("Archive = (%v, %v), want a directory", info, err)
	}

	// The listing, not the node a create was aimed at, is what describes a
	// directory that now exists.
	children, err := backend.List(ctx, dirNode(root))
	if err != nil || len(children) != 1 {
		t.Fatalf("List() = (%v, %v)", names(children), err)
	}
	if err := backend.Remove(ctx, children[0]); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	expectOnly(t, root)

	if err := backend.Remove(ctx, children[0]); !errors.Is(err, vfs.ErrNotExist) {
		t.Fatalf("Remove() of what is gone = %v, want no such file", err)
	}
}

func TestRenameMovesWithinOneDirectoryOnly(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	source := write(t, filepath.Join(root, "sub", "upload.tmp"), "contents", 0o644)
	backend := serve(t, root)
	ctx := context.Background()
	node := fileNode(source)

	if err := backend.Rename(ctx, node, "/sub/upload.tmp", "/sub/report.txt"); err != nil {
		t.Fatalf("Rename() error = %v", err)
	}
	expectOnly(t, filepath.Join(root, "sub"), "report.txt")

	// Where /elsewhere leads is the virtual filesystem's knowledge, so this
	// backend says what it cannot do rather than guessing at a destination.
	moved := fileNode(filepath.Join(root, "sub", "report.txt"))
	if err := backend.Rename(ctx, moved, "/sub/report.txt", "/elsewhere/report.txt"); !errors.Is(err, vfs.ErrUnsupported) {
		t.Fatalf("Rename() across directories = %v, want unsupported", err)
	}
	expectOnly(t, filepath.Join(root, "sub"), "report.txt")

	// A destination name is a name, never a path. The filesystem above rejects
	// one of these before a backend is reached; this refuses it regardless.
	if err := backend.Rename(ctx, moved, "/sub/report.txt", "/sub/.."); !errors.Is(err, vfs.ErrFailure) {
		t.Fatalf("Rename() to a traversal = %v, want failure", err)
	}
	if err := backend.Rename(ctx, masked(moved, 0o444), "/sub/report.txt", "/sub/other.txt"); !errors.Is(err, vfs.ErrPermission) {
		t.Fatalf("Rename() of a read-only node = %v, want permission denied", err)
	}
	expectOnly(t, filepath.Join(root, "sub"), "report.txt")
}

func TestChildCarriesTheDirectoryMaskAndUploadLimit(t *testing.T) {
	root := t.TempDir()
	backend := serve(t, root)
	directory := masked(dirNode(root), 0o750)
	directory.MaxUploadSize = 4096

	child, err := backend.Child(directory, "an odd name?#.txt")
	if err != nil {
		t.Fatalf("Child() error = %v", err)
	}
	if child.File != "an odd name?#.txt" || child.MaxUploadSize != 4096 {
		t.Errorf("child = %+v", child)
	}
	if child.Permissions == nil || *child.Permissions != 0o750 {
		t.Errorf("child permissions = %v, want the directory's mask", child.Permissions)
	}
	// A name with URL syntax in it is a name; it survives being written into one
	// and read back out.
	if path, ok := config.LocalPath(child.Backend); !ok || path != filepath.Join(root, "an odd name?#.txt") {
		t.Errorf("child backend %q resolves to (%q, %v)", child.Backend, path, ok)
	}
}

func TestNothingOfTheFilesystemTravelsWithAnError(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	backend := serve(t, root)
	ctx := context.Background()

	_, escaped := backend.Open(ctx, fileNode(filepath.Join(root, "escape", "secret.txt")))
	_, absent := backend.Open(ctx, fileNode(filepath.Join(root, "absent.txt")))
	_, outsideRoot := backend.List(ctx, dirNode(outside))

	for _, err := range []error{escaped, absent, outsideRoot} {
		if err == nil {
			t.Fatal("an operation that should have failed did not")
		}
		if strings.Contains(err.Error(), root) || strings.Contains(err.Error(), outside) {
			t.Errorf("error %q names the filesystem", err)
		}
	}
	// A refused escape is a plain failure: a client learns of it exactly what it
	// learns of any other.
	if !errors.Is(escaped, vfs.ErrFailure) {
		t.Errorf("escape error = %v, want failure", escaped)
	}
	if !errors.Is(absent, vfs.ErrNotExist) {
		t.Errorf("missing file error = %v, want no such file", absent)
	}
	if !errors.Is(outsideRoot, vfs.ErrPermission) {
		t.Errorf("outside error = %v, want permission denied", outsideRoot)
	}
}

// SFTP says a rename onto an existing name is an error rather than a
// replacement, which os.Rename would happily perform.
func TestRenameRefusesToOverwriteTheDestination(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "one.txt"), []byte("source"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "two.txt"), []byte("destination"), 0o644); err != nil {
		t.Fatal(err)
	}
	backend, err := New([]string{root})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = backend.Close() })

	node := vfs.Node{File: "one.txt", Backend: fileURL(filepath.Join(root, "one.txt"))}
	err = backend.Rename(context.Background(), node, "/one.txt", "/two.txt")
	if !errors.Is(err, vfs.ErrExist) {
		t.Fatalf("Rename() error = %v, want %v", err, vfs.ErrExist)
	}
	for name, want := range map[string]string{"one.txt": "source", "two.txt": "destination"} {
		contents, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || string(contents) != want {
			t.Errorf("%s = (%q, %v), want %q", name, contents, err, want)
		}
	}

	// A destination that is free is still renamed onto.
	if err := backend.Rename(context.Background(), node, "/one.txt", "/three.txt"); err != nil {
		t.Fatalf("Rename() to a free name error = %v", err)
	}
	if contents, err := os.ReadFile(filepath.Join(root, "three.txt")); err != nil || string(contents) != "source" {
		t.Errorf("three.txt = (%q, %v), want %q", contents, err, "source")
	}
}
