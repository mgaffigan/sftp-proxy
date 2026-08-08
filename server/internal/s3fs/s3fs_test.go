package s3fs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http/httptest"
	"strings"
	"testing"

	"sftp-proxy/internal/config"
	"sftp-proxy/internal/headers"
	"sftp-proxy/internal/vfs"
)

const bucketName = "acme-archive"

// serve stands a fake bucket up and returns a backend that has been told how to
// reach it, together with a helper naming URLs within it.
func serve(t *testing.T) (*Backend, *fakeS3, func(key string) string) {
	t.Helper()
	fake, endpoint := listen(t)
	backend, err := New(&config.S3Backend{Buckets: []config.S3Bucket{{
		Bucket:   bucketName,
		S3Access: access(endpoint),
	}}}, t.TempDir())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return backend, fake, func(key string) string { return "s3://" + bucketName + "/" + key }
}

func listen(t *testing.T) (*fakeS3, string) {
	t.Helper()
	fake := newFakeS3(bucketName)
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)
	return fake, server.URL
}

func access(endpoint string) config.S3Access {
	return config.S3Access{
		Region:          "us-east-1",
		Endpoint:        endpoint,
		AccessKeyID:     "AKIAEXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI",
	}
}

func directory(url string) vfs.Node { return vfs.Node{Directory: "docs", Backend: url} }
func file(url string) vfs.Node      { return vfs.Node{File: "one.txt", Backend: url} }

func names(children []vfs.Node) []string {
	found := make([]string, 0, len(children))
	for _, child := range children {
		kind := "file"
		if child.IsDirectory() {
			kind = "dir"
		}
		found = append(found, kind+" "+child.Name())
	}
	return found
}

func TestListReportsObjectsAndPrefixes(t *testing.T) {
	backend, fake, at := serve(t)
	fake.put("docs/one.txt", "first")
	fake.put("docs/two.txt", "second")
	fake.put("docs/sub/three.txt", "third")
	fake.put("elsewhere/four.txt", "fourth")

	children, err := backend.List(context.Background(), directory(at("docs")))
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	// Sorted by name, so a directory takes its place among the files rather
	// than ahead of them.
	want := []string{"file one.txt", "dir sub", "file two.txt"}
	if got := names(children); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("List() = %v, want %v", got, want)
	}
	if children[0].Size != int64(len("first")) {
		t.Errorf("one.txt size = %d, want %d", children[0].Size, len("first"))
	}
	if children[0].Mtime == nil || !children[0].Mtime.Equal(modified) {
		t.Errorf("one.txt mtime = %v, want %v", children[0].Mtime, modified)
	}
	if children[0].Backend != at("docs/one.txt") {
		t.Errorf("one.txt backend = %q, want %q", children[0].Backend, at("docs/one.txt"))
	}
	if children[1].Backend != at("docs/sub") {
		t.Errorf("sub backend = %q, want %q", children[1].Backend, at("docs/sub"))
	}
}

func TestListsTheBucketRoot(t *testing.T) {
	backend, fake, at := serve(t)
	fake.put("top.txt", "contents")
	fake.put("docs/one.txt", "first")

	children, err := backend.List(context.Background(), vfs.Node{Directory: "/", Backend: at("")})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	want := []string{"dir docs", "file top.txt"}
	if got := names(children); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("List() = %v, want %v", got, want)
	}
}

// A key equal to the prefix is the placeholder some tools write for a directory.
// It names nothing within the directory and must not appear as a member of it.
func TestListSkipsTheDirectoryPlaceholder(t *testing.T) {
	backend, fake, at := serve(t)
	fake.put("docs/", "")
	fake.put("docs/one.txt", "first")

	children, err := backend.List(context.Background(), directory(at("docs")))
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if got := names(children); strings.Join(got, ",") != "file one.txt" {
		t.Fatalf("List() = %v, want [file one.txt]", got)
	}
}

func TestListPresentsAnUnreadableDirectoryAsEmptyWithoutARequest(t *testing.T) {
	backend, fake, at := serve(t)
	fake.put("docs/one.txt", "first")

	node := directory(at("docs"))
	node.AllowedMethods = []string{config.S3PutObject}
	children, err := backend.List(context.Background(), node)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(children) != 0 {
		t.Errorf("List() = %v, want no children", names(children))
	}
	if fake.count() != 0 {
		t.Errorf("List() made %d requests, want 0", fake.count())
	}
}

// allowedMethods is stated again on every child, which is what makes a
// read-only directory a read-only subtree, and a child's displayed
// permissions are projected from it.
func TestListedChildrenCarryTheAllowedMethodsAndCredentials(t *testing.T) {
	fake, endpoint := listen(t)
	backend, err := New(&config.S3Backend{}, t.TempDir())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	fake.put("docs/one.txt", "first")
	fake.put("docs/sub/two.txt", "second")

	inline := access(endpoint)
	methods := []string{config.S3ListObjects, config.S3GetObject}
	node := vfs.Node{Directory: "docs", Backend: "s3://" + bucketName + "/docs", S3: &inline, AllowedMethods: methods}
	children, err := backend.List(context.Background(), node)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(children) != 2 {
		t.Fatalf("List() = %v, want two children", names(children))
	}
	for _, child := range children {
		if child.S3 != &inline {
			t.Errorf("%s credentials = %v, want the directory's", child.Name(), child.S3)
		}
		if strings.Join(child.AllowedMethods, ",") != strings.Join(methods, ",") {
			t.Errorf("%s allowedMethods = %v, want %v", child.Name(), child.AllowedMethods, methods)
		}
		if child.Permissions == nil || *child.Permissions != 0444 {
			t.Errorf("%s permissions = %v, want 0444", child.Name(), child.Permissions)
		}
	}
}

// The bucket table is the only other authority. A bucket in neither it nor the
// entry cannot be reached, however an entry names it.
func TestAnUnknownBucketIsUnreachable(t *testing.T) {
	backend, err := New(&config.S3Backend{}, t.TempDir())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = backend.List(context.Background(), vfs.Node{Directory: "docs", Backend: "s3://other-bucket/docs"})
	if !errors.Is(err, vfs.ErrPermission) {
		t.Fatalf("List() error = %v, want %v", err, vfs.ErrPermission)
	}
}

func TestOpenReadsRangesAndReportsSize(t *testing.T) {
	backend, fake, at := serve(t)
	fake.put("docs/one.txt", "abcdefghij")

	reader, err := backend.Open(context.Background(), file(at("docs/one.txt")))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer reader.Close()

	size, err := reader.Size()
	if err != nil || size != 10 {
		t.Fatalf("Size() = %d, %v, want 10, nil", size, err)
	}
	destination := make([]byte, 4)
	count, err := reader.ReadAt(destination, 3)
	if err != nil || count != 4 || string(destination) != "defg" {
		t.Fatalf("ReadAt() = %d, %q, %v, want 4, \"defg\", nil", count, destination, err)
	}
}

// The size is known before the first read, so a read that runs past the end is
// answered here rather than by asking for bytes that are not there.
func TestReadsPastTheEndAreAnsweredWithoutARequest(t *testing.T) {
	backend, fake, at := serve(t)
	fake.put("docs/one.txt", "abcde")

	reader, err := backend.Open(context.Background(), file(at("docs/one.txt")))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer reader.Close()

	destination := make([]byte, 4)
	if count, err := reader.ReadAt(destination, 3); count != 2 || !errors.Is(err, io.EOF) {
		t.Fatalf("ReadAt() = %d, %v, want 2, %v", count, err, io.EOF)
	}
	opened := fake.count()
	if count, err := reader.ReadAt(destination, 5); count != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("ReadAt() past the end = %d, %v, want 0, %v", count, err, io.EOF)
	}
	if fake.count() != opened {
		t.Errorf("ReadAt() past the end made %d requests, want 0", fake.count()-opened)
	}
}

func TestOpenReportsAMissingObject(t *testing.T) {
	backend, _, at := serve(t)
	if _, err := backend.Open(context.Background(), file(at("docs/absent.txt"))); !errors.Is(err, vfs.ErrNotExist) {
		t.Fatalf("Open() error = %v, want %v", err, vfs.ErrNotExist)
	}
}

func TestOpenRefusesAnUnreadableObjectAndTheBucketRoot(t *testing.T) {
	backend, fake, at := serve(t)
	fake.put("docs/one.txt", "first")

	node := file(at("docs/one.txt"))
	node.AllowedMethods = []string{config.S3PutObject}
	if _, err := backend.Open(context.Background(), node); !errors.Is(err, vfs.ErrPermission) {
		t.Fatalf("Open() error = %v, want %v", err, vfs.ErrPermission)
	}
	if _, err := backend.Open(context.Background(), vfs.Node{File: "root", Backend: at("")}); !errors.Is(err, vfs.ErrUnsupported) {
		t.Fatalf("Open() of the bucket root error = %v, want %v", err, vfs.ErrUnsupported)
	}
}

func TestCreateStoresTheStagedContentOnClose(t *testing.T) {
	backend, fake, at := serve(t)

	writer, err := backend.Create(context.Background(), file(at("docs/new.txt")))
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	// SFTP writes arrive at arbitrary offsets; the object is what they add up to.
	if _, err := writer.WriteAt([]byte("world"), 6); err != nil {
		t.Fatalf("WriteAt() error = %v", err)
	}
	if _, err := writer.WriteAt([]byte("hello "), 0); err != nil {
		t.Fatalf("WriteAt() error = %v", err)
	}
	if _, ok := fake.get("docs/new.txt"); ok {
		t.Fatal("the object exists before the writer was closed")
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if contents, ok := fake.get("docs/new.txt"); !ok || contents != "hello world" {
		t.Fatalf("stored %q, %v, want %q", contents, ok, "hello world")
	}
}

// upload stores contents at key through the backend, under whatever the context
// attributes the connection with.
func upload(t *testing.T, backend *Backend, ctx context.Context, node vfs.Node, contents string) {
	t.Helper()
	writer, err := backend.Create(ctx, node)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if _, err := writer.WriteAt([]byte(contents), 0); err != nil {
		t.Fatalf("WriteAt() error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestAnUploadIsStampedWithTheConnectionsHeaders(t *testing.T) {
	backend, fake, at := serve(t)
	stamp := map[string]string{"user-agent": "sftp-proxy", "user-agent-id": "acme"}

	upload(t, backend, headers.With(context.Background(), stamp), file(at("docs/new.txt")), "hello")

	if got := fake.meta("docs/new.txt"); !maps.Equal(got, stamp) {
		t.Fatalf("metadata = %v, want %v", got, stamp)
	}
}

func TestAnUploadUnderNoAttributionIsStampedWithNothing(t *testing.T) {
	backend, fake, at := serve(t)

	upload(t, backend, context.Background(), file(at("docs/new.txt")), "hello")

	if got := fake.meta("docs/new.txt"); len(got) != 0 {
		t.Fatalf("metadata = %v, want none", got)
	}
}

// TestRenameKeepsTheMetadataTheUploadWasStampedWith pins the COPY directive: an
// object says who put the bytes there, not who last moved them.
func TestRenameKeepsTheMetadataTheUploadWasStampedWith(t *testing.T) {
	backend, fake, at := serve(t)
	uploader := map[string]string{"user-agent-id": "acme"}
	mover := map[string]string{"user-agent-id": "someone-else"}

	upload(t, backend, headers.With(context.Background(), uploader), file(at("docs/one.txt")), "first")
	err := backend.Rename(headers.With(context.Background(), mover), file(at("docs/one.txt")), "/docs/one.txt", "/docs/two.txt")
	if err != nil {
		t.Fatalf("Rename() error = %v", err)
	}

	if got := fake.meta("docs/two.txt"); !maps.Equal(got, uploader) {
		t.Fatalf("metadata = %v, want %v", got, uploader)
	}
}

func TestAnAbortedUploadStoresNothing(t *testing.T) {
	backend, fake, at := serve(t)

	writer, err := backend.Create(context.Background(), file(at("docs/new.txt")))
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if _, err := writer.WriteAt([]byte("partial"), 0); err != nil {
		t.Fatalf("WriteAt() error = %v", err)
	}
	if err := writer.Abort(); err != nil {
		t.Fatalf("Abort() error = %v", err)
	}
	if _, ok := fake.get("docs/new.txt"); ok {
		t.Fatal("an aborted upload was stored")
	}
}

func TestCreateRefusesWhatAllowedMethodsWithholds(t *testing.T) {
	backend, _, at := serve(t)
	node := file(at("docs/new.txt"))
	node.AllowedMethods = []string{config.S3ListObjects, config.S3GetObject}
	if _, err := backend.Create(context.Background(), node); !errors.Is(err, vfs.ErrPermission) {
		t.Fatalf("Create() error = %v, want %v", err, vfs.ErrPermission)
	}
}

// A directory with no members has no prefix to be found by, so making one
// writes the marker at the prefix itself — which a listing then hides.
func TestMkdirAndRemoveTheDirectoryMarker(t *testing.T) {
	backend, fake, at := serve(t)
	ctx := context.Background()

	if err := backend.Mkdir(ctx, directory(at("docs/sub"))); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	if got := fake.keys(); strings.Join(got, ",") != "docs/sub/" {
		t.Fatalf("keys = %v, want [docs/sub/]", got)
	}
	children, err := backend.List(ctx, directory(at("docs")))
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if got := names(children); strings.Join(got, ",") != "dir sub" {
		t.Fatalf("List() = %v, want [dir sub]", got)
	}
	if children, err := backend.List(ctx, directory(at("docs/sub"))); err != nil || len(children) != 0 {
		t.Fatalf("List() of a fresh directory = %v, %v, want empty", names(children), err)
	}

	if err := backend.Remove(ctx, directory(at("docs/sub"))); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	if got := fake.keys(); len(got) != 0 {
		t.Fatalf("keys = %v, want none", got)
	}
}

// Emptying a directory is a walk rather than a request, which is not what
// rmdir asked for.
func TestRemoveRefusesADirectoryWithMembers(t *testing.T) {
	backend, fake, at := serve(t)
	fake.put("docs/sub/", "")
	fake.put("docs/sub/one.txt", "first")

	if err := backend.Remove(context.Background(), directory(at("docs/sub"))); !errors.Is(err, vfs.ErrFailure) {
		t.Fatalf("Remove() error = %v, want %v", err, vfs.ErrFailure)
	}
	if _, ok := fake.get("docs/sub/"); !ok {
		t.Error("Remove() took the marker of a directory it refused to remove")
	}
}

// The bucket root is always there, so it can be neither made nor removed.
func TestMkdirAndRemoveRefuseTheBucketRoot(t *testing.T) {
	backend, _, at := serve(t)
	root := vfs.Node{Directory: "/", Backend: at("")}

	if err := backend.Mkdir(context.Background(), root); !errors.Is(err, vfs.ErrUnsupported) {
		t.Errorf("Mkdir() error = %v, want %v", err, vfs.ErrUnsupported)
	}
	if err := backend.Remove(context.Background(), root); !errors.Is(err, vfs.ErrUnsupported) {
		t.Errorf("Remove() error = %v, want %v", err, vfs.ErrUnsupported)
	}
}

func TestMkdirAndDirectoryRemovalObeyAllowedMethods(t *testing.T) {
	backend, fake, at := serve(t)
	fake.put("docs/sub/", "")
	ctx := context.Background()

	readOnly := directory(at("docs/sub"))
	readOnly.AllowedMethods = []string{config.S3ListObjects, config.S3GetObject}
	if err := backend.Mkdir(ctx, readOnly); !errors.Is(err, vfs.ErrPermission) {
		t.Errorf("Mkdir() error = %v, want %v", err, vfs.ErrPermission)
	}
	if err := backend.Remove(ctx, readOnly); !errors.Is(err, vfs.ErrPermission) {
		t.Errorf("Remove() error = %v, want %v", err, vfs.ErrPermission)
	}
	// A directory that cannot be listed cannot be shown to be empty either.
	unlistable := directory(at("docs/sub"))
	unlistable.AllowedMethods = []string{config.S3DeleteObject}
	if err := backend.Remove(ctx, unlistable); !errors.Is(err, vfs.ErrPermission) {
		t.Errorf("Remove() without ListObjectsV2 error = %v, want %v", err, vfs.ErrPermission)
	}
}

// Deleting a key that is not there succeeds at S3, so asking first is what makes
// removing something that has gone report that it has gone.
func TestRemoveReportsAMissingObject(t *testing.T) {
	backend, fake, at := serve(t)
	fake.put("docs/one.txt", "first")

	if err := backend.Remove(context.Background(), file(at("docs/one.txt"))); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	if _, ok := fake.get("docs/one.txt"); ok {
		t.Fatal("Remove() left the object behind")
	}
	if err := backend.Remove(context.Background(), file(at("docs/one.txt"))); !errors.Is(err, vfs.ErrNotExist) {
		t.Fatalf("Remove() of a missing object error = %v, want %v", err, vfs.ErrNotExist)
	}
}

func TestRenameCopiesAndDeletesWithinTheDirectory(t *testing.T) {
	backend, fake, at := serve(t)
	fake.put("docs/one.txt", "first")

	err := backend.Rename(context.Background(), file(at("docs/one.txt")), "/docs/one.txt", "/docs/two.txt")
	if err != nil {
		t.Fatalf("Rename() error = %v", err)
	}
	want := []string{"docs/two.txt"}
	if got := fake.keys(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("keys = %v, want %v", got, want)
	}
	if contents, _ := fake.get("docs/two.txt"); contents != "first" {
		t.Errorf("contents = %q, want %q", contents, "first")
	}
}

func TestRenameEscapesTheSourceItNames(t *testing.T) {
	backend, fake, at := serve(t)
	fake.put("docs/one two.txt", "first")

	node := vfs.Node{File: "one two.txt", Backend: at("docs/one%20two.txt")}
	if err := backend.Rename(context.Background(), node, "/docs/one two.txt", "/docs/three four.txt"); err != nil {
		t.Fatalf("Rename() error = %v", err)
	}
	if contents, ok := fake.get("docs/three four.txt"); !ok || contents != "first" {
		t.Fatalf("stored %q, %v, want %q", contents, ok, "first")
	}
}

// Where a virtual path leads is the filesystem's knowledge rather than a
// backend's, so a destination anywhere else is refused rather than guessed at.
func TestRenameRefusesToLeaveTheDirectory(t *testing.T) {
	backend, fake, at := serve(t)
	fake.put("docs/one.txt", "first")

	err := backend.Rename(context.Background(), file(at("docs/one.txt")), "/docs/one.txt", "/elsewhere/one.txt")
	if !errors.Is(err, vfs.ErrUnsupported) {
		t.Fatalf("Rename() error = %v, want %v", err, vfs.ErrUnsupported)
	}
	if _, ok := fake.get("docs/one.txt"); !ok {
		t.Fatal("a refused rename moved the object")
	}
}

func TestChildAppendsOneEscapedSegmentAndCarriesCreationPolicy(t *testing.T) {
	backend, _, at := serve(t)
	node := directory(at("docs"))
	node.AllowedMethods = []string{config.S3ListObjects, config.S3GetObject, config.S3PutObject}
	node.MaxUploadSize = 4096

	child, err := backend.Child(node, "hello world.txt")
	if err != nil {
		t.Fatalf("Child() error = %v", err)
	}
	if child.Backend != at("docs/hello%20world.txt") {
		t.Errorf("Child() backend = %q, want %q", child.Backend, at("docs/hello%20world.txt"))
	}
	if child.File != "hello world.txt" || child.IsDirectory() {
		t.Errorf("Child() = %+v, want a file named %q", child, "hello world.txt")
	}
	if child.MaxUploadSize != 4096 {
		t.Errorf("Child() maxUploadSize = %d, want 4096", child.MaxUploadSize)
	}
	if strings.Join(child.AllowedMethods, ",") != strings.Join(node.AllowedMethods, ",") {
		t.Errorf("Child() allowedMethods = %v, want %v", child.AllowedMethods, node.AllowedMethods)
	}
	if child.Permissions == nil || *child.Permissions != 0666 {
		t.Errorf("Child() permissions = %v, want 0666", child.Permissions)
	}
}

// A name given to Child is a name whatever it contains, and reading it back is
// what proves the escaping and the unescaping agree.
func TestAnEscapedNameRoundTrips(t *testing.T) {
	backend, _, at := serve(t)
	child, err := backend.Child(directory(at("docs")), "hello world.txt")
	if err != nil {
		t.Fatalf("Child() error = %v", err)
	}
	writer, err := backend.Create(context.Background(), child)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if _, err := writer.WriteAt([]byte("contents"), 0); err != nil {
		t.Fatalf("WriteAt() error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	children, err := backend.List(context.Background(), directory(at("docs")))
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if got := names(children); strings.Join(got, ",") != "file hello world.txt" {
		t.Fatalf("List() = %v, want [file hello world.txt]", got)
	}
	reader, err := backend.Open(context.Background(), children[0])
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer reader.Close()
	destination := make([]byte, len("contents"))
	if _, err := reader.ReadAt(destination, 0); err != nil {
		t.Fatalf("ReadAt() error = %v", err)
	}
	if string(destination) != "contents" {
		t.Errorf("ReadAt() = %q, want %q", destination, "contents")
	}
}

// Credentials on an entry are what let a proxy serve a bucket it was never
// configured for.
func TestInlineCredentialsReachAnUnconfiguredBucket(t *testing.T) {
	fake, endpoint := listen(t)
	backend, err := New(&config.S3Backend{}, t.TempDir())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	fake.put("docs/one.txt", "first")

	inline := access(endpoint)
	node := vfs.Node{Directory: "docs", Backend: "s3://" + bucketName + "/docs", S3: &inline}
	children, err := backend.List(context.Background(), node)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if got := names(children); strings.Join(got, ",") != "file one.txt" {
		t.Fatalf("List() = %v, want [file one.txt]", got)
	}
}

func TestIncompleteInlineCredentialsAreRefused(t *testing.T) {
	fake, endpoint := listen(t)
	backend, err := New(&config.S3Backend{}, t.TempDir())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	fake.put("docs/one.txt", "first")

	inline := access(endpoint)
	inline.SecretAccessKey = ""
	node := vfs.Node{Directory: "docs", Backend: "s3://" + bucketName + "/docs", S3: &inline}
	if _, err := backend.List(context.Background(), node); !errors.Is(err, vfs.ErrFailure) {
		t.Fatalf("List() error = %v, want %v", err, vfs.ErrFailure)
	}
	if fake.count() != 0 {
		t.Errorf("List() made %d requests, want 0", fake.count())
	}
}

func TestARefusedRequestIsAPermissionOutcome(t *testing.T) {
	backend, fake, at := serve(t)
	fake.put("docs/one.txt", "first")
	fake.refuse()

	if _, err := backend.List(context.Background(), directory(at("docs"))); !errors.Is(err, vfs.ErrPermission) {
		t.Fatalf("List() error = %v, want %v", err, vfs.ErrPermission)
	}
	if _, err := backend.Open(context.Background(), file(at("docs/one.txt"))); !errors.Is(err, vfs.ErrPermission) {
		t.Fatalf("Open() error = %v, want %v", err, vfs.ErrPermission)
	}
}

// The four outcomes are all a client may learn. A bucket name, a key, or the
// endpoint serving them would otherwise travel to it in an error string.
func TestErrorsCarryNothingOfTheBackend(t *testing.T) {
	backend, fake, at := serve(t)
	fake.put("docs/one.txt", "first")
	fake.refuse()

	ctx := context.Background()
	writer, createErr := backend.Create(ctx, file(at("docs/one.txt")))
	var commitErr error
	if createErr == nil {
		if _, err := writer.WriteAt([]byte("contents"), 0); err != nil {
			t.Fatalf("WriteAt() error = %v", err)
		}
		commitErr = writer.Close()
	}
	_, listErr := backend.List(ctx, directory(at("docs")))
	_, openErr := backend.Open(ctx, file(at("docs/one.txt")))
	removeErr := backend.Remove(ctx, file(at("docs/one.txt")))
	renameErr := backend.Rename(ctx, file(at("docs/one.txt")), "/docs/one.txt", "/docs/two.txt")

	failures := []error{commitErr, listErr, openErr, removeErr, renameErr}
	for index, err := range failures {
		if err == nil {
			t.Fatalf("failures[%d] = nil, want a refusal to inspect", index)
		}
	}

	secrets := []string{bucketName, "docs/one.txt", "object-store.example.invalid", "AKIAEXAMPLE", "wJalrXUtnFEMI"}
	for _, err := range append(failures, createErr) {
		if err == nil {
			continue
		}
		for _, secret := range secrets {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("error %q names %q", err, secret)
			}
		}
	}
}

func TestNewRejectsAMissingConfiguration(t *testing.T) {
	if _, err := New(nil, t.TempDir()); err == nil {
		t.Fatal("New(nil) error = nil, want an error")
	}
}

func TestReadAtRefusesANegativeOffsetAndAnswersAnEmptyRead(t *testing.T) {
	backend, fake, at := serve(t)
	fake.put("docs/one.txt", "abcde")

	reader, err := backend.Open(context.Background(), file(at("docs/one.txt")))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer reader.Close()

	if _, err := reader.ReadAt(make([]byte, 4), -1); !errors.Is(err, vfs.ErrFailure) {
		t.Errorf("ReadAt(-1) error = %v, want %v", err, vfs.ErrFailure)
	}
	opened := fake.count()
	if count, err := reader.ReadAt(nil, 0); count != 0 || err != nil {
		t.Errorf("ReadAt(nil) = %d, %v, want 0, nil", count, err)
	}
	if fake.count() != opened {
		t.Errorf("an empty read made %d requests, want 0", fake.count()-opened)
	}
}

// A read that fails partway is the operation failing, not the file ending.
func TestReadAtReportsAFailureAfterTheFileWasOpened(t *testing.T) {
	backend, fake, at := serve(t)
	fake.put("docs/one.txt", "abcde")

	reader, err := backend.Open(context.Background(), file(at("docs/one.txt")))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer reader.Close()

	fake.refuse()
	if _, err := reader.ReadAt(make([]byte, 4), 0); !errors.Is(err, vfs.ErrPermission) {
		t.Errorf("ReadAt() error = %v, want %v", err, vfs.ErrPermission)
	}
}

// A store that promises a range and sends less of it has ended the object early,
// which is EOF rather than a lie the caller has to detect for itself.
func TestReadAtTreatsATruncatedRangeAsTheEnd(t *testing.T) {
	backend, fake, at := serve(t)
	fake.put("docs/one.txt", "abcdefghij")
	fake.truncateBodies()

	reader, err := backend.Open(context.Background(), file(at("docs/one.txt")))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer reader.Close()

	destination := make([]byte, 8)
	count, err := reader.ReadAt(destination, 0)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("ReadAt() error = %v, want %v", err, io.EOF)
	}
	if count >= 8 {
		t.Errorf("ReadAt() = %d, want a short read", count)
	}
}

// Where a name and a prefix collide the directory wins, because it is the one of
// the two a client can still descend into.
func TestListPrefersADirectoryOverAKeyOfTheSameName(t *testing.T) {
	backend, fake, at := serve(t)
	fake.put("docs/sub", "a key that shares a name with a prefix")
	fake.put("docs/sub/one.txt", "first")

	children, err := backend.List(context.Background(), directory(at("docs")))
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if got := names(children); strings.Join(got, ",") != "dir sub" {
		t.Fatalf("List() = %v, want [dir sub]", got)
	}
}

func TestAMalformedBackendURLIsAFailure(t *testing.T) {
	backend, _, _ := serve(t)
	ctx := context.Background()
	node := vfs.Node{Directory: "docs", Backend: "s3://Not A Bucket/docs"}

	if _, err := backend.List(ctx, node); !errors.Is(err, vfs.ErrFailure) {
		t.Errorf("List() error = %v, want %v", err, vfs.ErrFailure)
	}
	if _, err := backend.Child(node, "one.txt"); !errors.Is(err, vfs.ErrFailure) {
		t.Errorf("Child() error = %v, want %v", err, vfs.ErrFailure)
	}
}

// A bucket root is a directory, so it is not somewhere a file can be written.
func TestCreateRefusesTheBucketRoot(t *testing.T) {
	backend, _, at := serve(t)
	if _, err := backend.Create(context.Background(), vfs.Node{File: "root", Backend: at("")}); !errors.Is(err, vfs.ErrUnsupported) {
		t.Fatalf("Create() error = %v, want %v", err, vfs.ErrUnsupported)
	}
}

func TestRemoveAndRenameRefuseWhatAllowedMethodsWithholds(t *testing.T) {
	backend, fake, at := serve(t)
	fake.put("docs/one.txt", "first")

	node := file(at("docs/one.txt"))
	node.AllowedMethods = []string{config.S3ListObjects, config.S3GetObject}
	ctx := context.Background()
	if err := backend.Remove(ctx, node); !errors.Is(err, vfs.ErrPermission) {
		t.Errorf("Remove() error = %v, want %v", err, vfs.ErrPermission)
	}
	if err := backend.Rename(ctx, node, "/docs/one.txt", "/docs/two.txt"); !errors.Is(err, vfs.ErrPermission) {
		t.Errorf("Rename() error = %v, want %v", err, vfs.ErrPermission)
	}
	if _, ok := fake.get("docs/one.txt"); !ok {
		t.Error("a refused change altered the store")
	}
}

// The destination is validated rather than trusted, so a name that is not one
// cannot be assembled into a key.
func TestRenameRefusesADestinationThatIsNotAName(t *testing.T) {
	backend, fake, at := serve(t)
	fake.put("docs/one.txt", "first")

	ctx := context.Background()
	for _, to := range []string{"/docs/..", "/docs/."} {
		if err := backend.Rename(ctx, file(at("docs/one.txt")), "/docs/one.txt", to); !errors.Is(err, vfs.ErrFailure) {
			t.Errorf("Rename() to %q error = %v, want %v", to, err, vfs.ErrFailure)
		}
	}
	if keys := fake.keys(); strings.Join(keys, ",") != "docs/one.txt" {
		t.Errorf("keys = %v, want the original alone", keys)
	}
}

func TestRenameRefusesADirectory(t *testing.T) {
	backend, fake, at := serve(t)
	fake.put("docs/sub/one.txt", "first")

	err := backend.Rename(context.Background(), directory(at("docs/sub")), "/docs/sub", "/docs/other")
	if !errors.Is(err, vfs.ErrUnsupported) {
		t.Fatalf("Rename() of a directory error = %v, want %v", err, vfs.ErrUnsupported)
	}
}

// Anything the four outcomes do not describe is a plain failure, with the cause
// left on the span rather than handed to a client.
func TestAnUnrecognizedFailureIsGeneric(t *testing.T) {
	backend, fake, at := serve(t)
	fake.put("docs/one.txt", "first")
	fake.breakDown()

	ctx := context.Background()
	if _, err := backend.List(ctx, directory(at("docs"))); !errors.Is(err, vfs.ErrFailure) {
		t.Errorf("List() error = %v, want %v", err, vfs.ErrFailure)
	}
	if _, err := backend.Open(ctx, file(at("docs/one.txt"))); !errors.Is(err, vfs.ErrFailure) {
		t.Errorf("Open() error = %v, want %v", err, vfs.ErrFailure)
	}
}

// Ambient credentials are the proxy's own identity, resolved once at startup.
// Only a configuration file can ask for them.
func TestABucketMayUseTheAmbientIdentity(t *testing.T) {
	fake, endpoint := listen(t)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAAMBIENT")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "ambientsecret")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	fake.put("docs/one.txt", "first")

	backend, err := New(&config.S3Backend{Buckets: []config.S3Bucket{{
		Bucket:                bucketName,
		UseDefaultCredentials: true,
		S3Access:              config.S3Access{Region: "us-east-1", Endpoint: endpoint},
	}}}, t.TempDir())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	children, err := backend.List(context.Background(), directory("s3://"+bucketName+"/docs"))
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if got := names(children); strings.Join(got, ",") != "file one.txt" {
		t.Fatalf("List() = %v, want [file one.txt]", got)
	}
}

// SFTP says a rename onto an existing name is an error rather than a
// replacement, so the destination is asked about before anything is copied.
func TestRenameRefusesToOverwriteTheDestination(t *testing.T) {
	backend, fake, at := serve(t)
	fake.put("docs/one.txt", "source")
	fake.put("docs/two.txt", "a destination that already exists")

	err := backend.Rename(context.Background(), file(at("docs/one.txt")), "/docs/one.txt", "/docs/two.txt")
	if !errors.Is(err, vfs.ErrExist) {
		t.Fatalf("Rename() error = %v, want %v", err, vfs.ErrExist)
	}
	if contents, _ := fake.get("docs/two.txt"); contents != "a destination that already exists" {
		t.Errorf("two.txt = %q, want it untouched", contents)
	}
	if contents, _ := fake.get("docs/one.txt"); contents != "source" {
		t.Errorf("one.txt = %q, want it left where it was", contents)
	}
}

// A prefix is not a directory and nothing limits how many keys share one, so a
// listing that would be unreasonable fails rather than returning the first part
// of itself, which a client could not tell from the whole thing.
func TestAnEnormousListingIsRefusedRatherThanTruncated(t *testing.T) {
	// The limit is a stated policy, not an accident of tuning.
	if maxListingEntries != 10000 {
		t.Fatalf("maxListingEntries = %d, want 10000", maxListingEntries)
	}
	backend, fake, at := serve(t)
	for index := range maxListingEntries {
		fake.put(fmt.Sprintf("docs/%06d.txt", index), "x")
	}

	children, err := backend.List(context.Background(), directory(at("docs")))
	if err != nil {
		t.Fatalf("List() of exactly the limit error = %v", err)
	}
	if len(children) != maxListingEntries {
		t.Fatalf("List() = %d children, want %d", len(children), maxListingEntries)
	}

	fake.put("docs/one-too-many.txt", "x")
	if _, err := backend.List(context.Background(), directory(at("docs"))); !errors.Is(err, vfs.ErrFailure) {
		t.Fatalf("List() past the limit error = %v, want %v", err, vfs.ErrFailure)
	}
}
