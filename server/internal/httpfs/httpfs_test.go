package httpfs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"sftp-proxy/internal/vfs"
)

// serve starts a backend and returns a Backend pointed at it, along with a URL
// builder for the paths the handler recognises.
func serve(t *testing.T, handler http.HandlerFunc) (*Backend, func(string) string) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return New(server.Client(), t.TempDir()), func(path string) string { return server.URL + path }
}

func directory(writer http.ResponseWriter, body string) {
	writer.Header().Set("Content-Type", directoryContentType)
	_, _ = writer.Write([]byte(body))
}

func TestListDecodesADirectoryListing(t *testing.T) {
	backend, url := serve(t, func(writer http.ResponseWriter, request *http.Request) {
		directory(writer, `{"children":[
			{"file":"report.txt","size":4,"mtime":"2026-08-07T12:34:56Z","permissions":416,"backend":"https://files.test/report.txt"},
			{"directory":"sub","backend":"https://files.test/sub"}
		]}`)
	})

	children, err := backend.List(context.Background(), vfs.Node{Directory: "d", Backend: url("/d")})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(children) != 2 {
		t.Fatalf("children = %+v", children)
	}
	if children[0].Name() != "report.txt" || children[0].Size != 4 || children[0].IsDirectory() {
		t.Errorf("file child = %+v", children[0])
	}
	wantMtime := time.Date(2026, time.August, 7, 12, 34, 56, 0, time.UTC)
	if children[0].Mtime == nil || !children[0].Mtime.Equal(wantMtime) || children[0].Permissions == nil || *children[0].Permissions != 0640 {
		t.Errorf("file metadata = mtime %v, permissions %v", children[0].Mtime, children[0].Permissions)
	}
	if children[1].Name() != "sub" || !children[1].IsDirectory() {
		t.Errorf("directory child = %+v", children[1])
	}
}

func TestListRejectsAWrongContentTypeOrAnInvalidEntry(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"wrong content type": func(writer http.ResponseWriter, request *http.Request) {
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"children":[]}`))
		},
		"unknown field": func(writer http.ResponseWriter, request *http.Request) {
			directory(writer, `{"children":[{"file":"a.txt","backend":"https://f.test/a","surprise":1}]}`)
		},
		"invalid entry": func(writer http.ResponseWriter, request *http.Request) {
			directory(writer, `{"children":[{"file":"../escape","backend":"https://f.test/a"}]}`)
		},
		"traversal in a name": func(writer http.ResponseWriter, request *http.Request) {
			directory(writer, `{"children":[{"directory":"..","backend":"https://f.test/a"}]}`)
		},
	}
	for name, handler := range cases {
		t.Run(name, func(t *testing.T) {
			backend, url := serve(t, handler)
			_, err := backend.List(context.Background(), vfs.Node{Directory: "d", Backend: url("/d")})
			if !errors.Is(err, vfs.ErrFailure) {
				t.Fatalf("List() error = %v, want failure", err)
			}
		})
	}
}

func TestListPresentsAnUnlistableDirectoryAsEmpty(t *testing.T) {
	requests := 0
	backend, url := serve(t, func(writer http.ResponseWriter, request *http.Request) {
		requests++
		writer.WriteHeader(http.StatusMethodNotAllowed)
	})
	node := vfs.Node{Directory: "d", Backend: url("/d")}

	// A backend that declines to list still accepts uploads, so this is an
	// empty directory rather than an error.
	children, err := backend.List(context.Background(), node)
	if err != nil || len(children) != 0 {
		t.Fatalf("List() = (%v, %v), want (empty, nil)", children, err)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want 1", requests)
	}

	// Declaring the directory upload-only keeps the request from being made
	// at all, which is what allowedMethods is for.
	node.AllowedMethods = []string{http.MethodPost}
	children, err = backend.List(context.Background(), node)
	if err != nil || len(children) != 0 {
		t.Fatalf("List() = (%v, %v), want (empty, nil)", children, err)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want the refusal to be local", requests)
	}
}

func TestAllowedMethodsRefuseLocallyWithoutARequest(t *testing.T) {
	requests := 0
	backend, url := serve(t, func(writer http.ResponseWriter, request *http.Request) {
		requests++
		writer.WriteHeader(http.StatusOK)
	})
	ctx := context.Background()
	readOnly := vfs.Node{File: "f.txt", Backend: url("/f.txt"), AllowedMethods: []string{http.MethodGet}}

	if _, err := backend.Create(ctx, readOnly); !errors.Is(err, vfs.ErrPermission) {
		t.Errorf("Create() error = %v, want permission denied", err)
	}
	if err := backend.Remove(ctx, readOnly); !errors.Is(err, vfs.ErrPermission) {
		t.Errorf("Remove() error = %v, want permission denied", err)
	}
	if err := backend.Rename(ctx, readOnly, "/other.txt"); !errors.Is(err, vfs.ErrPermission) {
		t.Errorf("Rename() error = %v, want permission denied", err)
	}
	if err := backend.Mkdir(ctx, readOnly); !errors.Is(err, vfs.ErrPermission) {
		t.Errorf("Mkdir() error = %v, want permission denied", err)
	}
	writeOnly := vfs.Node{File: "f.txt", Backend: url("/f.txt"), AllowedMethods: []string{http.MethodPost}}
	if _, err := backend.Open(ctx, writeOnly); !errors.Is(err, vfs.ErrPermission) {
		t.Errorf("Open() error = %v, want permission denied", err)
	}
	if requests != 0 {
		t.Fatalf("requests = %d, want every refusal to be local", requests)
	}
}

func TestCreatePostsTheStagedContentOnClose(t *testing.T) {
	var method, contentType, body string
	posts := 0
	backend, url := serve(t, func(writer http.ResponseWriter, request *http.Request) {
		posts++
		method, contentType = request.Method, request.Header.Get("Content-Type")
		contents, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
		}
		body = string(contents)
		writer.WriteHeader(http.StatusOK)
	})

	writer, err := backend.Create(context.Background(), vfs.Node{File: "up.txt", Backend: url("/up.txt")})
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
	if posts != 0 {
		t.Fatal("content was sent before the writer was closed")
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if method != http.MethodPost || contentType != uploadContentType || body != "hello world" {
		t.Fatalf("upload = (%s, %s, %q)", method, contentType, body)
	}
}

func TestMkdirPostsTheDirectoryEntryType(t *testing.T) {
	var method, contentType string
	backend, url := serve(t, func(writer http.ResponseWriter, request *http.Request) {
		method, contentType = request.Method, request.Header.Get("Content-Type")
		writer.WriteHeader(http.StatusOK)
	})

	if err := backend.Mkdir(context.Background(), vfs.Node{Directory: "new", Backend: url("/new")}); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	if method != http.MethodPost || contentType != directoryEntryContentType {
		t.Fatalf("mkdir = (%s, %s)", method, contentType)
	}
}

func TestRemoveAndRenameBothDelete(t *testing.T) {
	var requested string
	backend, url := serve(t, func(writer http.ResponseWriter, request *http.Request) {
		requested = request.Method + " " + request.URL.RequestURI()
		writer.WriteHeader(http.StatusOK)
	})
	ctx := context.Background()
	node := vfs.Node{File: "f.txt", Backend: url("/f.txt")}

	if err := backend.Remove(ctx, node); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	if requested != "DELETE /f.txt" {
		t.Fatalf("remove sent %q", requested)
	}

	// A rename is the same DELETE, carrying where the node should end up.
	if err := backend.Rename(ctx, node, "/some dir/moved.txt"); err != nil {
		t.Fatalf("Rename() error = %v", err)
	}
	if requested != "DELETE /f.txt?renameTo=%2Fsome+dir%2Fmoved.txt" {
		t.Fatalf("rename sent %q", requested)
	}
}

func TestChildAppendsOneSegmentAndCarriesCreationPolicy(t *testing.T) {
	backend := New(http.DefaultClient, t.TempDir())
	parent := vfs.Node{
		Directory:      "d",
		Backend:        "https://files.test/base/d/",
		AllowedMethods: []string{http.MethodPost},
		MaxUploadSize:  42,
	}

	child, err := backend.Child(parent, "new file.txt")
	if err != nil {
		t.Fatalf("Child() error = %v", err)
	}
	if child.Backend != "https://files.test/base/d/new%20file.txt" {
		t.Fatalf("child URL = %q", child.Backend)
	}
	if child.Name() != "new file.txt" || child.IsDirectory() {
		t.Fatalf("child = %+v", child)
	}
	// A node that does not exist yet has no methods of its own, so creating it
	// is governed by the directory that will hold it.
	if len(child.AllowedMethods) != 1 || child.AllowedMethods[0] != http.MethodPost {
		t.Fatalf("child methods = %v", child.AllowedMethods)
	}
	if child.MaxUploadSize != 42 {
		t.Fatalf("child max upload size = %d, want 42", child.MaxUploadSize)
	}
}

func TestStatusesBecomeOutcomes(t *testing.T) {
	cases := []struct {
		status int
		want   error
	}{
		{http.StatusUnauthorized, vfs.ErrPermission},
		{http.StatusForbidden, vfs.ErrPermission},
		{http.StatusNotFound, vfs.ErrNotExist},
		{http.StatusMethodNotAllowed, vfs.ErrUnsupported},
		{http.StatusInternalServerError, vfs.ErrFailure},
		{http.StatusTeapot, vfs.ErrFailure},
	}
	for _, testCase := range cases {
		backend, url := serve(t, func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(testCase.status)
		})
		err := backend.Remove(context.Background(), vfs.Node{File: "f", Backend: url("/f")})
		if !errors.Is(err, testCase.want) {
			t.Errorf("status %d became %v, want %v", testCase.status, err, testCase.want)
		}
	}
}

func TestErrorsCarryNothingOfTheBackend(t *testing.T) {
	backend, url := serve(t, func(writer http.ResponseWriter, request *http.Request) {
		http.Error(writer, "secret: /var/private/path leaked", http.StatusInternalServerError)
	})
	err := backend.Remove(context.Background(), vfs.Node{File: "f", Backend: url("/f")})
	if err == nil || err.Error() != vfs.ErrFailure.Error() {
		t.Fatalf("error = %v, want the bare failure sentinel", err)
	}
}

func TestOpenReadsARange(t *testing.T) {
	var requestedRange string
	backend, url := serve(t, func(writer http.ResponseWriter, request *http.Request) {
		requestedRange = request.Header.Get("Range")
		writer.WriteHeader(http.StatusPartialContent)
		_, _ = writer.Write([]byte("port"))
	})

	reader, err := backend.Open(context.Background(), vfs.Node{File: "f", Backend: url("/f")})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer reader.Close()

	data := make([]byte, 4)
	if count, err := reader.ReadAt(data, 12); count != 4 || err != nil {
		t.Fatalf("ReadAt() = (%d, %v), want (4, nil)", count, err)
	}
	if string(data) != "port" || requestedRange != "bytes=12-15" {
		t.Fatalf("read %q for range %q", data, requestedRange)
	}
}

func TestOpenReportsEOFAtTheEndOfAFile(t *testing.T) {
	t.Run("short final range", func(t *testing.T) {
		backend, url := serve(t, func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusPartialContent)
			_, _ = writer.Write([]byte("last"))
		})
		reader, err := backend.Open(context.Background(), vfs.Node{File: "f", Backend: url("/f")})
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		defer reader.Close()
		count, err := reader.ReadAt(make([]byte, 8), 0)
		if count != 4 || !errors.Is(err, io.EOF) {
			t.Fatalf("ReadAt() = (%d, %v), want (4, EOF)", count, err)
		}
	})

	t.Run("range past the end", func(t *testing.T) {
		backend, url := serve(t, func(writer http.ResponseWriter, request *http.Request) {
			writer.Header().Set("Content-Range", "bytes */10")
			writer.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		})
		reader, err := backend.Open(context.Background(), vfs.Node{File: "f", Backend: url("/f")})
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		defer reader.Close()
		count, err := reader.ReadAt(make([]byte, 32768), 32768)
		if count != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("ReadAt() = (%d, %v), want (0, EOF)", count, err)
		}
	})
}

// contents serves a file over ranges the way a conforming backend does,
// counting the requests it took and clamping a range that runs off the end.
func contents(body string, requests *int) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		*requests++
		var first, last int64
		if _, err := fmt.Sscanf(request.Header.Get("Range"), "bytes=%d-%d", &first, &last); err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		if first >= int64(len(body)) {
			writer.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", len(body)))
			writer.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return
		}
		last = min(last, int64(len(body))-1)
		writer.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", first, last, len(body)))
		writer.WriteHeader(http.StatusPartialContent)
		_, _ = writer.Write([]byte(body[first : last+1]))
	}
}

func TestOpenSpendsOneRequestPerRead(t *testing.T) {
	requests := 0
	backend, url := serve(t, contents("0123456789ab", &requests))
	reader, err := backend.Open(context.Background(), vfs.Node{File: "f", Backend: url("/f")})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer reader.Close()

	// The first read classifies the backend as part of doing its own work, so
	// it costs no more than the ones after it.
	for index, offset := range []int64{0, 8, 4} {
		buffer := make([]byte, 4)
		count, err := reader.ReadAt(buffer, offset)
		if count != 4 || err != nil {
			t.Fatalf("ReadAt(%d) = (%d, %v)", offset, count, err)
		}
		if want := "0123456789ab"[offset : offset+4]; string(buffer) != want {
			t.Fatalf("ReadAt(%d) read %q, want %q", offset, buffer, want)
		}
		if requests != index+1 {
			t.Fatalf("requests = %d after %d reads", requests, index+1)
		}
	}
}

func TestOpenAnswersPastTheEndWithoutARequest(t *testing.T) {
	requests := 0
	backend, url := serve(t, contents("last", &requests))
	reader, err := backend.Open(context.Background(), vfs.Node{File: "f", Backend: url("/f")})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer reader.Close()

	// One read is enough to learn the length from Content-Range.
	if count, err := reader.ReadAt(make([]byte, 8), 0); count != 4 || !errors.Is(err, io.EOF) {
		t.Fatalf("ReadAt() = (%d, %v), want (4, EOF)", count, err)
	}
	// A client's read-ahead past the end is answered here rather than sent on
	// to be refused with a 416.
	for _, offset := range []int64{4, 32768} {
		if count, err := reader.ReadAt(make([]byte, 8), offset); count != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("ReadAt(%d) = (%d, %v), want (0, EOF)", offset, count, err)
		}
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want the reads past the end to cost nothing", requests)
	}
}

func TestOpenLearnsTheLengthFromARefusedRange(t *testing.T) {
	requests := 0
	backend, url := serve(t, contents("", &requests))
	reader, err := backend.Open(context.Background(), vfs.Node{File: "f", Backend: url("/f")})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer reader.Close()

	// An empty file refuses every range, and says so with a length.
	for range 3 {
		if count, err := reader.ReadAt(make([]byte, 8), 0); count != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("ReadAt() = (%d, %v), want (0, EOF)", count, err)
		}
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want 1", requests)
	}
}

func TestOpenKeepsReadingWhenNoLengthIsStated(t *testing.T) {
	requests := 0
	backend, url := serve(t, func(writer http.ResponseWriter, request *http.Request) {
		requests++
		// Both a header that states no total and one that cannot be parsed
		// leave the length unknown.
		writer.Header().Set("Content-Range", []string{"bytes 0-3/*", "gibberish"}[requests%2])
		writer.WriteHeader(http.StatusPartialContent)
		_, _ = writer.Write([]byte("data"))
	})
	reader, err := backend.Open(context.Background(), vfs.Node{File: "f", Backend: url("/f")})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer reader.Close()

	// Not knowing the length costs requests, never correctness.
	for range 3 {
		buffer := make([]byte, 4)
		if count, err := reader.ReadAt(buffer, 0); count != 4 || err != nil || string(buffer) != "data" {
			t.Fatalf("ReadAt() = (%d, %q, %v)", count, buffer, err)
		}
	}
	if requests != 3 {
		t.Fatalf("requests = %d, want one per read", requests)
	}
}

func TestOpenStagesOnceUnderConcurrentFirstReads(t *testing.T) {
	var mu sync.Mutex
	requests := 0
	backend, url := serve(t, func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		// 200 with the whole body: the range was ignored.
		_, _ = writer.Write([]byte("0123456789ab"))
	})
	reader, err := backend.Open(context.Background(), vfs.Node{File: "f", Backend: url("/f")})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer reader.Close()

	// A client opens a file with a burst of pipelined reads. Only one of them
	// may discover that this backend answers with the whole file; the rest wait
	// for what it learns rather than each downloading their own copy.
	var group sync.WaitGroup
	for index := range 12 {
		offset := int64(index % 3 * 4)
		group.Go(func() {
			buffer := make([]byte, 4)
			count, err := reader.ReadAt(buffer, offset)
			if count != 4 || err != nil {
				t.Errorf("ReadAt(%d) = (%d, %v)", offset, count, err)
				return
			}
			if want := "0123456789ab"[offset : offset+4]; string(buffer) != want {
				t.Errorf("ReadAt(%d) read %q, want %q", offset, buffer, want)
			}
		})
	}
	group.Wait()

	mu.Lock()
	defer mu.Unlock()
	if requests != 1 {
		t.Fatalf("requests = %d, want the whole file fetched once", requests)
	}
}

func TestOpenRefusesAWholeFileAfterARangedRead(t *testing.T) {
	requests := 0
	backend, url := serve(t, func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if requests == 1 {
			writer.Header().Set("Content-Range", "bytes 0-3/64")
			writer.WriteHeader(http.StatusPartialContent)
			_, _ = writer.Write([]byte("data"))
			return
		}
		// The same backend, having served one range as a range, now ignores the
		// header and answers with the whole file.
		_, _ = writer.Write([]byte("the whole file"))
	})
	reader, err := backend.Open(context.Background(), vfs.Node{File: "f", Backend: url("/f")})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer reader.Close()

	if count, err := reader.ReadAt(make([]byte, 4), 0); count != 4 || err != nil {
		t.Fatalf("ReadAt() = (%d, %v), want (4, nil)", count, err)
	}
	// Staging belongs to the reader this file was not given, and a body that
	// cannot be seeked within is no answer to a read at an offset.
	if count, err := reader.ReadAt(make([]byte, 4), 8); count != 0 || !errors.Is(err, vfs.ErrFailure) {
		t.Fatalf("ReadAt() = (%d, %v), want (0, failure)", count, err)
	}
}

func TestReadAfterCloseFails(t *testing.T) {
	requests := 0
	backend, url := serve(t, contents("0123456789ab", &requests))
	reader, err := backend.Open(context.Background(), vfs.Node{File: "f", Backend: url("/f")})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if count, err := reader.ReadAt(make([]byte, 4), 0); count != 4 || err != nil {
		t.Fatalf("ReadAt() = (%d, %v), want (4, nil)", count, err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if count, err := reader.ReadAt(make([]byte, 4), 0); count != 0 || !errors.Is(err, vfs.ErrFailure) {
		t.Fatalf("ReadAt() after Close = (%d, %v), want (0, failure)", count, err)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want the read after Close to be refused locally", requests)
	}
}

func TestCloseDuringTheFirstReadRefusesIt(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		close(started)
		<-release
		// The whole file, which the reader would otherwise stage and hold open.
		_, _ = writer.Write([]byte("whole file"))
	}))
	defer server.Close()
	backend := New(server.Client(), t.TempDir())

	reader, err := backend.Open(context.Background(), vfs.Node{File: "f", Backend: server.URL + "/f"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	outcome := make(chan error, 1)
	go func() {
		_, err := reader.ReadAt(make([]byte, 4), 0)
		outcome <- err
	}()

	// Close the handle with the first read still in flight. What that read goes
	// on to build must not outlive it, so the read is refused rather than
	// adopted, and the staged copy it made is closed where it was made.
	<-started
	if err := reader.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	close(release)
	if err := <-outcome; !errors.Is(err, vfs.ErrFailure) {
		t.Fatalf("ReadAt() during Close = %v, want failure", err)
	}
}

func TestOpenStagesABackendThatIgnoresRange(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		// 200 with the whole body: the range was ignored.
		_, _ = writer.Write([]byte("fallback"))
	}))
	defer server.Close()
	staging := t.TempDir()
	backend := New(server.Client(), staging)

	reader, err := backend.Open(context.Background(), vfs.Node{File: "f", Backend: server.URL + "/f"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	buffer := make([]byte, 4)
	if count, err := reader.ReadAt(buffer, 4); count != 4 || err != nil || string(buffer) != "back" {
		t.Fatalf("ReadAt() = (%d, %q, %v)", count, buffer, err)
	}
	// Every later read is served from the staged copy rather than re-fetched.
	if count, err := reader.ReadAt(buffer, 0); count != 4 || err != nil || string(buffer) != "fall" {
		t.Fatalf("ReadAt() = (%d, %q, %v)", count, buffer, err)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want 1", requests)
	}

	// The staged copy is unlinked as soon as it is created, so it is servicing
	// those reads while already absent from the directory. Nothing is left to
	// clean up if the process dies mid-download.
	if left, err := os.ReadDir(staging); err != nil || len(left) != 0 {
		t.Fatalf("staging directory holds %d entries (%v) while the download is open", len(left), err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestOpenRejectsATruncatedWholeFileFallback(t *testing.T) {
	requests := 0
	backend, url := serve(t, func(writer http.ResponseWriter, request *http.Request) {
		requests++
		writer.Header().Set("Content-Length", "8")
		_, _ = writer.Write([]byte("fall"))
	})
	reader, err := backend.Open(context.Background(), vfs.Node{File: "f", Backend: url("/f")})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer reader.Close()

	for range 2 {
		if count, err := reader.ReadAt(make([]byte, 4), 0); count != 0 || !errors.Is(err, vfs.ErrFailure) {
			t.Fatalf("ReadAt() = (%d, %v), want (0, failure)", count, err)
		}
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2 after rejected staging", requests)
	}
}

func TestRedirectsMayLeaveTheBackend(t *testing.T) {
	elsewhere := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodDelete {
			t.Errorf("redirected method = %s, want DELETE", request.Method)
		}
		writer.WriteHeader(http.StatusOK)
	}))
	defer elsewhere.Close()

	backend, url := serve(t, func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, elsewhere.URL+"/signed", http.StatusTemporaryRedirect)
	})

	if err := backend.Remove(context.Background(), vfs.Node{File: "away", Backend: url("/base/away")}); err != nil {
		t.Fatalf("Remove() across origins = %v", err)
	}
}
