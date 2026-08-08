package httpfs

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

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
			{"file":"report.txt","size":4,"backend":"https://files.test/report.txt"},
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
	// at all, which is what allowed_methods is for.
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

func TestChildAppendsOneSegmentAndCarriesTheDirectorysMethods(t *testing.T) {
	backend := New(http.DefaultClient, t.TempDir())
	parent := vfs.Node{
		Directory:      "d",
		Backend:        "https://files.test/base/d/",
		AllowedMethods: []string{http.MethodPost},
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

func TestRedirectsMayNotLeaveTheBackend(t *testing.T) {
	elsewhere := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		t.Error("a redirect escaped the configured backend")
	}))
	defer elsewhere.Close()

	backend, url := serve(t, func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/base/away":
			http.Redirect(writer, request, elsewhere.URL+"/", http.StatusFound)
		case "/base/near":
			http.Redirect(writer, request, "/base/near/final", http.StatusFound)
		default:
			writer.WriteHeader(http.StatusOK)
		}
	})
	ctx := context.Background()

	err := backend.Remove(ctx, vfs.Node{File: "away", Backend: url("/base/away")})
	if !errors.Is(err, vfs.ErrFailure) {
		t.Fatalf("Remove() across origins = %v, want failure", err)
	}
	// A redirect staying under the same base is followed normally.
	if err := backend.Remove(ctx, vfs.Node{File: "near", Backend: url("/base/near")}); err != nil {
		t.Fatalf("Remove() within the backend = %v", err)
	}
}
