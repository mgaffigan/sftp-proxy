package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"path"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"sftp-proxy/internal/config"
	"sftp-proxy/internal/vfs"
)

func TestParseSCPCommand(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    scpCommand
		wantOK  bool
	}{
		{name: "sink", command: "scp -t /Workspace", want: scpCommand{sink: true, path: "/Workspace"}, wantOK: true},
		{name: "source", command: "scp -f file.txt", want: scpCommand{source: true, path: "file.txt"}, wantOK: true},
		{
			name:    "end of flags",
			command: "scp -t -- -weird-name",
			want:    scpCommand{sink: true, path: "-weird-name"},
			wantOK:  true,
		},
		{
			name:    "clustered flags",
			command: "scp -rpdt /Workspace",
			want:    scpCommand{sink: true, recursive: true, preserve: true, directory: true, path: "/Workspace"},
			wantOK:  true,
		},
		{
			name:    "single quoted path",
			command: "scp -f 'Some Directory/a file.txt'",
			want:    scpCommand{source: true, path: "Some Directory/a file.txt"},
			wantOK:  true,
		},
		{
			name:    "double quoted path with escape",
			command: `scp -t "quoted \"name\""`,
			want:    scpCommand{sink: true, path: `quoted "name"`},
			wantOK:  true,
		},
		{
			name:    "backslash escaped space",
			command: `scp -f /Workspace/a\ b.txt`,
			want:    scpCommand{source: true, path: "/Workspace/a b.txt"},
			wantOK:  true,
		},
		{name: "absolute program name", command: "/usr/bin/scp -t .", want: scpCommand{sink: true, path: "."}, wantOK: true},
		{name: "verbosity ignored", command: "scp -v -q -t .", want: scpCommand{sink: true, path: "."}, wantOK: true},

		{name: "not scp", command: "rm -rf /"},
		{name: "shell chained command", command: "scp -t /Workspace; rm -rf /"},
		{name: "no direction", command: "scp -r /Workspace"},
		{name: "both directions", command: "scp -t -f /Workspace"},
		{name: "unknown flag", command: "scp -t -z /Workspace"},
		{name: "no operand", command: "scp -t"},
		{name: "two operands", command: "scp -t /one /two"},
		{name: "unbalanced quote", command: "scp -t 'unterminated"},
		{name: "empty", command: ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := parseSCPCommand(test.command)
			if ok != test.wantOK {
				t.Fatalf("parseSCPCommand(%q) ok = %v, want %v", test.command, ok, test.wantOK)
			}
			if ok && got != test.want {
				t.Errorf("parseSCPCommand(%q) = %+v, want %+v", test.command, got, test.want)
			}
		})
	}
}

func TestVirtualPath(t *testing.T) {
	tests := []struct {
		raw     string
		want    string
		wantErr bool
	}{
		{raw: ".", want: "/"},
		{raw: "", want: "/"},
		{raw: "~", want: "/"},
		{raw: "~/Workspace", want: "/Workspace"},
		{raw: "Workspace/file.txt", want: "/Workspace/file.txt"},
		{raw: "/Workspace/./file.txt", want: "/Workspace/file.txt"},
		{raw: "/Workspace/sub/../file.txt", want: "/Workspace/file.txt"},
		// Traversal past the top collapses against the root, as it does on a
		// real filesystem, rather than reaching anything above it.
		{raw: "/../../etc/passwd", want: "/etc/passwd"},
		{raw: "../../etc/passwd", want: "/etc/passwd"},
		{raw: "~someone/files", wantErr: true},
		{raw: "/Workspace/\x00", wantErr: true},
	}

	for _, test := range tests {
		got, err := virtualPath(test.raw)
		if test.wantErr {
			if err == nil {
				t.Errorf("virtualPath(%q) = %q, want error", test.raw, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("virtualPath(%q) error = %v", test.raw, err)
			continue
		}
		if got != test.want {
			t.Errorf("virtualPath(%q) = %q, want %q", test.raw, got, test.want)
		}
	}
}

func TestSCPSinkWritesIntoDirectory(t *testing.T) {
	backend := newMemoryBackend()
	backend.addDirectory("/Workspace")
	exchange := runSCP(t, scpCommand{sink: true, path: "/Workspace"}, backend, 0)

	exchange.expectAck()
	exchange.write("C0644 8 up.txt\n")
	exchange.expectAck()
	exchange.write("contents")
	exchange.write("\x00")
	exchange.expectAck()

	if !exchange.finish() {
		t.Fatalf("session failed, stderr = %q", exchange.stderr())
	}
	backend.expectFile(t, "/Workspace/up.txt", "contents")
}

func TestSCPSinkWritesFileAtExactTarget(t *testing.T) {
	backend := newMemoryBackend()
	backend.addDirectory("/Workspace")
	// The target does not exist, so it names the file rather than a directory
	// to put it in: this is what `scp a.txt host:/Workspace/b.txt` means.
	exchange := runSCP(t, scpCommand{sink: true, path: "/Workspace/renamed.txt"}, backend, 0)

	exchange.expectAck()
	exchange.write("C0644 5 source.txt\n")
	exchange.expectAck()
	exchange.write("hello\x00")
	exchange.expectAck()

	if !exchange.finish() {
		t.Fatalf("session failed, stderr = %q", exchange.stderr())
	}
	backend.expectFile(t, "/Workspace/renamed.txt", "hello")
	backend.expectAbsent(t, "/Workspace/source.txt")
}

func TestSCPSinkCreatesDirectoryTree(t *testing.T) {
	backend := newMemoryBackend()
	backend.addDirectory("/Workspace")
	exchange := runSCP(t, scpCommand{sink: true, recursive: true, path: "/Workspace"}, backend, 0)

	exchange.expectAck()
	exchange.write("D0755 0 tree\n")
	exchange.expectAck()
	exchange.write("C0644 3 leaf.txt\n")
	exchange.expectAck()
	exchange.write("abc\x00")
	exchange.expectAck()
	exchange.write("D0755 0 nested\n")
	exchange.expectAck()
	exchange.write("C0644 2 deep.txt\n")
	exchange.expectAck()
	exchange.write("hi\x00")
	exchange.expectAck()
	exchange.write("E\n")
	exchange.expectAck()
	exchange.write("E\n")
	exchange.expectAck()

	if !exchange.finish() {
		t.Fatalf("session failed, stderr = %q", exchange.stderr())
	}
	backend.expectFile(t, "/Workspace/tree/leaf.txt", "abc")
	backend.expectFile(t, "/Workspace/tree/nested/deep.txt", "hi")
}

func TestSCPSinkStaysReadablePastARefusedDirectory(t *testing.T) {
	backend := newMemoryBackend()
	backend.addDirectory("/Workspace")
	backend.refuseMkdir["/Workspace/denied"] = struct{}{}
	exchange := runSCP(t, scpCommand{sink: true, recursive: true, path: "/Workspace"}, backend, 0)

	exchange.expectAck()
	exchange.write("D0755 0 denied\n")
	if status := exchange.readStatus(); status != scpWarning {
		t.Fatalf("directory status = %d, want %d", status, scpWarning)
	}
	exchange.readLine()

	// The client sends the refused directory's contents and its E regardless, so
	// each entry is refused on its own and the stream stays where it should be.
	exchange.write("C0644 3 inside.txt\n")
	if status := exchange.readStatus(); status != scpWarning {
		t.Fatalf("file status = %d, want %d", status, scpWarning)
	}
	exchange.readLine()
	exchange.write("E\n")
	exchange.expectAck()

	// Back at the top, where the client can still be served.
	exchange.write("C0644 4 after.txt\n")
	exchange.expectAck()
	exchange.write("done\x00")
	exchange.expectAck()

	if exchange.finish() {
		t.Fatal("session succeeded, want the refusal in the exit status")
	}
	backend.expectFile(t, "/Workspace/after.txt", "done")
	backend.expectAbsent(t, "/Workspace/denied/inside.txt")
}

func TestSCPSinkRejectsNameOutsideTarget(t *testing.T) {
	backend := newMemoryBackend()
	backend.addDirectory("/Workspace")
	exchange := runSCP(t, scpCommand{sink: true, path: "/Workspace"}, backend, 0)

	exchange.expectAck()
	exchange.write("C0644 4 ../escaped.txt\n")

	// A name the client made up is checked rather than trusted, so this never
	// reaches the filesystem and the session ends without one being written.
	if exchange.finish() {
		t.Fatal("session succeeded, want failure")
	}
	backend.expectAbsent(t, "/escaped.txt")
	backend.expectAbsent(t, "/Workspace/escaped.txt")
}

func TestSCPSinkDiscardsAbandonedUpload(t *testing.T) {
	backend := newMemoryBackend()
	backend.addDirectory("/Workspace")
	exchange := runSCP(t, scpCommand{sink: true, path: "/Workspace"}, backend, 0)

	exchange.expectAck()
	exchange.write("C0644 9 partial.txt\n")
	exchange.expectAck()
	exchange.write("truncated")
	// The client's own verdict on what it just sent. A file it gave up on must
	// not appear whole under the name it was going to have.
	exchange.write("\x01sending failed\n")

	if exchange.finish() {
		t.Fatal("session succeeded, want failure")
	}
	backend.expectAbsent(t, "/Workspace/partial.txt")
}

func TestSCPSinkRefusesWhenUploadLimitReached(t *testing.T) {
	backend := newMemoryBackend()
	backend.addDirectory("/Workspace")
	// Another channel on this connection is already holding the only slot.
	factory := newHandlerFactory(backend.filesystem(), 1)
	if _, ok := factory.uploads.acquire(); !ok {
		t.Fatal("could not take the first upload slot")
	}
	exchange := runSCPWithFactory(t, scpCommand{sink: true, path: "/Workspace"}, factory)

	exchange.expectAck()
	exchange.write("C0644 4 late.txt\n")
	if status := exchange.readStatus(); status != scpWarning {
		t.Fatalf("status = %d, want %d", status, scpWarning)
	}
	message := exchange.readLine()
	exchange.closeClient()

	if exchange.finish() {
		t.Fatal("session succeeded, want failure")
	}
	if !strings.Contains(message, "late.txt") {
		t.Errorf("message = %q, want it to name the file", message)
	}
	backend.expectAbsent(t, "/Workspace/late.txt")
}

func TestSCPSinkRequiresDirectoryTarget(t *testing.T) {
	backend := newMemoryBackend()
	// -d says the client will only accept a directory, and there is none here.
	exchange := runSCP(t, scpCommand{sink: true, directory: true, path: "/Missing"}, backend, 0)

	if exchange.finish() {
		t.Fatal("session succeeded, want failure")
	}
	if !strings.Contains(exchange.stderr(), vfs.ErrNotExist.Error()) {
		t.Errorf("stderr = %q, want it to report no such file", exchange.stderr())
	}
}

func TestSCPSourceSendsFile(t *testing.T) {
	backend := newMemoryBackend()
	backend.addFile("/report.csv", "id,total\n1,42\n")
	exchange := runSCP(t, scpCommand{source: true, path: "/report.csv"}, backend, 0)

	exchange.write("\x00")
	if header := exchange.readLine(); header != "C0644 14 report.csv" {
		t.Fatalf("header = %q, want the file's exact length", header)
	}
	exchange.write("\x00")
	if contents := exchange.read(14); contents != "id,total\n1,42\n" {
		t.Errorf("contents = %q", contents)
	}
	if status := exchange.readStatus(); status != scpOK {
		t.Errorf("status = %d, want %d", status, scpOK)
	}
	exchange.write("\x00")

	if !exchange.finish() {
		t.Fatalf("session failed, stderr = %q", exchange.stderr())
	}
}

func TestSCPCarriesAnEmptyFile(t *testing.T) {
	backend := newMemoryBackend()
	backend.addDirectory("/Workspace")

	upload := runSCP(t, scpCommand{sink: true, path: "/Workspace"}, backend, 0)
	upload.expectAck()
	upload.write("C0644 0 empty.txt\n")
	upload.expectAck()
	upload.write("\x00")
	upload.expectAck()
	if !upload.finish() {
		t.Fatalf("upload failed, stderr = %q", upload.stderr())
	}
	backend.expectFile(t, "/Workspace/empty.txt", "")

	download := runSCP(t, scpCommand{source: true, path: "/Workspace/empty.txt"}, backend, 0)
	download.write("\x00")
	if header := download.readLine(); header != "C0644 0 empty.txt" {
		t.Fatalf("header = %q", header)
	}
	download.write("\x00")
	if status := download.readStatus(); status != scpOK {
		t.Fatalf("status = %d, want %d", status, scpOK)
	}
	download.write("\x00")
	if !download.finish() {
		t.Fatalf("download failed, stderr = %q", download.stderr())
	}
}

func TestSCPSourceSendsTimesWhenPreserving(t *testing.T) {
	backend := newMemoryBackend()
	backend.addFile("/dated.txt", "x")
	when := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	backend.mtimes["/dated.txt"] = when
	exchange := runSCP(t, scpCommand{source: true, preserve: true, path: "/dated.txt"}, backend, 0)

	exchange.write("\x00")
	if times := exchange.readLine(); times != fmt.Sprintf("T%d 0 %d 0", when.Unix(), when.Unix()) {
		t.Fatalf("times = %q", times)
	}
	exchange.write("\x00")
	if header := exchange.readLine(); header != "C0644 1 dated.txt" {
		t.Fatalf("header = %q", header)
	}
	exchange.write("\x00")
	exchange.read(1)
	exchange.readStatus()
	exchange.write("\x00")

	if !exchange.finish() {
		t.Fatalf("session failed, stderr = %q", exchange.stderr())
	}
}

func TestSCPSourceWalksDirectory(t *testing.T) {
	backend := newMemoryBackend()
	backend.addDirectory("/Workspace")
	backend.addDirectory("/Workspace/nested")
	backend.addFile("/Workspace/a.txt", "aa")
	backend.addFile("/Workspace/nested/b.txt", "bbb")
	exchange := runSCP(t, scpCommand{source: true, recursive: true, path: "/Workspace"}, backend, 0)

	exchange.write("\x00")
	want := []string{
		"D0755 0 Workspace",
		"C0644 2 a.txt",
		"D0755 0 nested",
		"C0644 3 b.txt",
		"E",
		"E",
	}
	var got []string
	for range want {
		line := exchange.readLine()
		got = append(got, line)
		exchange.write("\x00")
		if strings.HasPrefix(line, "C") {
			size, _, err := parseSCPFileHeader(line)
			if err != nil {
				t.Fatalf("header %q: %v", line, err)
			}
			exchange.read(int(size))
			exchange.readStatus()
			exchange.write("\x00")
		}
	}
	if !slices.Equal(got, want) {
		t.Errorf("transfer =\n%v\nwant\n%v", got, want)
	}
	if !exchange.finish() {
		t.Fatalf("session failed, stderr = %q", exchange.stderr())
	}
}

func TestSCPSourceRefusesDirectoryWithoutRecursion(t *testing.T) {
	backend := newMemoryBackend()
	backend.addDirectory("/Workspace")
	exchange := runSCP(t, scpCommand{source: true, path: "/Workspace"}, backend, 0)

	exchange.write("\x00")
	if status := exchange.readStatus(); status != scpWarning {
		t.Fatalf("status = %d, want %d", status, scpWarning)
	}
	if message := exchange.readLine(); !strings.Contains(message, vfs.ErrUnsupported.Error()) {
		t.Errorf("message = %q", message)
	}
	exchange.closeClient()
	if exchange.finish() {
		t.Fatal("session succeeded, want failure")
	}
}

func TestSCPSourceRefusesFileOfUnknownSize(t *testing.T) {
	backend := newMemoryBackend()
	backend.addFile("/unmeasured.bin", "contents")
	// A backend that never states a length leaves nothing to put in the header.
	backend.sizeless["/unmeasured.bin"] = struct{}{}
	exchange := runSCP(t, scpCommand{source: true, path: "/unmeasured.bin"}, backend, 0)

	exchange.write("\x00")
	if status := exchange.readStatus(); status != scpWarning {
		t.Fatalf("status = %d, want %d", status, scpWarning)
	}
	if message := exchange.readLine(); !strings.Contains(message, vfs.ErrUnsupported.Error()) {
		t.Errorf("message = %q", message)
	}
	exchange.closeClient()
	if exchange.finish() {
		t.Fatal("session succeeded, want failure")
	}
}

func TestSCPMessagesNameNoBackend(t *testing.T) {
	backend := newMemoryBackend()
	exchange := runSCP(t, scpCommand{source: true, path: "/absent.txt"}, backend, 0)

	exchange.write("\x00")
	exchange.readStatus()
	message := exchange.readLine()
	exchange.closeClient()
	exchange.finish()

	if strings.Contains(message, memoryScheme) {
		t.Errorf("message = %q, want no backend URL in it", message)
	}
	if !strings.Contains(message, vfs.ErrNotExist.Error()) {
		t.Errorf("message = %q, want the outcome", message)
	}
}

// scpExchange runs one SCP session and lets a test play the client at the other
// end of its channel. The protocol takes turns, so the session runs on its own
// goroutine and the test drives an unbuffered pipe against it.
type scpExchange struct {
	t      *testing.T
	client net.Conn
	errors *bytes.Buffer
	done   chan bool
}

type testChannel struct {
	net.Conn
	errors *bytes.Buffer
}

func (c *testChannel) Stderr() io.ReadWriter { return c.errors }

func runSCP(t *testing.T, command scpCommand, backend *memoryBackend, maxConcurrentUploads int) *scpExchange {
	t.Helper()
	return runSCPWithFactory(t, command, newHandlerFactory(backend.filesystem(), maxConcurrentUploads))
}

func runSCPWithFactory(t *testing.T, command scpCommand, factory *handlerFactory) *scpExchange {
	t.Helper()
	serverSide, clientSide := net.Pipe()
	if err := clientSide.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("SetDeadline() error = %v", err)
	}
	channel := &testChannel{Conn: serverSide, errors: &bytes.Buffer{}}

	done := make(chan bool, 1)
	go func() {
		done <- factory.scp(command, channel).run(context.Background())
		_ = serverSide.Close()
	}()
	exchange := &scpExchange{t: t, client: clientSide, errors: channel.errors, done: done}
	t.Cleanup(func() { _ = clientSide.Close() })
	return exchange
}

func (e *scpExchange) write(data string) {
	e.t.Helper()
	if _, err := io.WriteString(e.client, data); err != nil {
		e.t.Fatalf("write(%q) error = %v", data, err)
	}
}

func (e *scpExchange) read(count int) string {
	e.t.Helper()
	buffer := make([]byte, count)
	if _, err := io.ReadFull(e.client, buffer); err != nil {
		e.t.Fatalf("read(%d) error = %v", count, err)
	}
	return string(buffer)
}

func (e *scpExchange) readStatus() byte {
	e.t.Helper()
	return e.read(1)[0]
}

func (e *scpExchange) expectAck() {
	e.t.Helper()
	if status := e.readStatus(); status != scpOK {
		e.t.Fatalf("status = %d, want %d (%q)", status, scpOK, e.readLine())
	}
}

func (e *scpExchange) readLine() string {
	e.t.Helper()
	var line strings.Builder
	for {
		character := e.read(1)
		if character == "\n" {
			return line.String()
		}
		line.WriteString(character)
	}
}

func (e *scpExchange) closeClient() {
	e.t.Helper()
	if err := e.client.Close(); err != nil {
		e.t.Fatalf("Close() error = %v", err)
	}
}

// finish lets the session see the end of the stream and reports its outcome,
// which is the exit status the client would be given.
func (e *scpExchange) finish() bool {
	e.t.Helper()
	_ = e.client.Close()
	select {
	case succeeded := <-e.done:
		return succeeded
	case <-time.After(10 * time.Second):
		e.t.Fatal("session did not finish")
		return false
	}
}

func (e *scpExchange) stderr() string { return e.errors.String() }

// memoryBackend is a whole filesystem in a map, so that the SCP tests exercise
// the protocol rather than a stack of stubs.
const memoryScheme = "mem"

type memoryBackend struct {
	mu          sync.Mutex
	files       map[string]string
	directories map[string]struct{}
	mtimes      map[string]time.Time
	sizeless    map[string]struct{}
	refuseMkdir map[string]struct{}
}

func newMemoryBackend() *memoryBackend {
	return &memoryBackend{
		files:       map[string]string{},
		directories: map[string]struct{}{"/": {}},
		mtimes:      map[string]time.Time{},
		sizeless:    map[string]struct{}{},
		refuseMkdir: map[string]struct{}{},
	}
}

func (b *memoryBackend) filesystem() *vfs.FS {
	return vfs.New(config.RootFS{Backend: memoryURL("/")}, vfs.Backends{memoryScheme: b})
}

func memoryURL(virtual string) string { return memoryScheme + "://files" + virtual }

func memoryPath(node vfs.Node) string {
	parsed, err := url.Parse(node.Backend)
	if err != nil || parsed.Path == "" {
		return "/"
	}
	return parsed.Path
}

func (b *memoryBackend) addDirectory(virtual string) {
	b.directories[virtual] = struct{}{}
}

func (b *memoryBackend) addFile(virtual, contents string) {
	b.files[virtual] = contents
}

func (b *memoryBackend) expectFile(t *testing.T, virtual, want string) {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	got, ok := b.files[virtual]
	if !ok {
		t.Fatalf("%s was not written", virtual)
	}
	if got != want {
		t.Errorf("%s = %q, want %q", virtual, got, want)
	}
}

func (b *memoryBackend) expectAbsent(t *testing.T, virtual string) {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	if contents, ok := b.files[virtual]; ok {
		t.Errorf("%s exists with %q, want it absent", virtual, contents)
	}
}

func (b *memoryBackend) node(virtual string) vfs.Node {
	node := vfs.Node{Backend: memoryURL(virtual)}
	if _, ok := b.directories[virtual]; ok {
		node.Directory = path.Base(virtual)
		return node
	}
	node.File = path.Base(virtual)
	node.Size = int64(len(b.files[virtual]))
	if when, ok := b.mtimes[virtual]; ok {
		node.Mtime = &when
	}
	return node
}

func (b *memoryBackend) List(_ context.Context, node vfs.Node) ([]vfs.Node, error) {
	directory := memoryPath(node)
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.directories[directory]; !ok {
		return nil, vfs.ErrNotExist
	}

	var children []vfs.Node
	for name := range b.directories {
		if name != "/" && path.Dir(name) == directory {
			children = append(children, b.node(name))
		}
	}
	for name := range b.files {
		if path.Dir(name) == directory {
			children = append(children, b.node(name))
		}
	}
	slices.SortFunc(children, func(left, right vfs.Node) int {
		return strings.Compare(left.Name(), right.Name())
	})
	return children, nil
}

func (b *memoryBackend) Open(_ context.Context, node vfs.Node) (vfs.ReaderAtCloser, error) {
	virtual := memoryPath(node)
	b.mu.Lock()
	defer b.mu.Unlock()
	contents, ok := b.files[virtual]
	if !ok {
		return nil, vfs.ErrNotExist
	}
	_, sizeless := b.sizeless[virtual]
	return &memoryReader{contents: contents, sizeless: sizeless}, nil
}

func (b *memoryBackend) Create(_ context.Context, node vfs.Node) (vfs.WriterAtCloser, error) {
	virtual := memoryPath(node)
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.directories[path.Dir(virtual)]; !ok {
		return nil, vfs.ErrNotExist
	}
	return &memoryWriter{backend: b, path: virtual}, nil
}

func (b *memoryBackend) Mkdir(_ context.Context, node vfs.Node) error {
	virtual := memoryPath(node)
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.refuseMkdir[virtual]; ok {
		return vfs.ErrPermission
	}
	if _, ok := b.directories[path.Dir(virtual)]; !ok {
		return vfs.ErrNotExist
	}
	b.directories[virtual] = struct{}{}
	return nil
}

func (b *memoryBackend) Remove(_ context.Context, node vfs.Node) error {
	virtual := memoryPath(node)
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.files, virtual)
	delete(b.directories, virtual)
	return nil
}

func (b *memoryBackend) Rename(context.Context, vfs.Node, string, string) error {
	return vfs.ErrUnsupported
}

func (b *memoryBackend) Child(node vfs.Node, name string) (vfs.Node, error) {
	return vfs.Node{File: name, Backend: memoryURL(path.Join(memoryPath(node), name))}, nil
}

type memoryReader struct {
	contents string
	sizeless bool
}

func (r *memoryReader) ReadAt(destination []byte, offset int64) (int, error) {
	if offset >= int64(len(r.contents)) {
		return 0, io.EOF
	}
	count := copy(destination, r.contents[offset:])
	if count < len(destination) {
		return count, io.EOF
	}
	return count, nil
}

func (r *memoryReader) Size() (int64, error) {
	if r.sizeless {
		return 0, vfs.ErrUnsupported
	}
	return int64(len(r.contents)), nil
}

func (r *memoryReader) Close() error { return nil }

type memoryWriter struct {
	backend  *memoryBackend
	path     string
	contents []byte
}

func (w *memoryWriter) WriteAt(data []byte, offset int64) (int, error) {
	if end := offset + int64(len(data)); int64(len(w.contents)) < end {
		w.contents = append(w.contents, make([]byte, end-int64(len(w.contents)))...)
	}
	copy(w.contents[offset:], data)
	return len(data), nil
}

func (w *memoryWriter) Close() error {
	w.backend.mu.Lock()
	defer w.backend.mu.Unlock()
	w.backend.files[w.path] = string(w.contents)
	return nil
}

func (w *memoryWriter) Abort() error {
	w.contents = nil
	return nil
}

var _ vfs.Backend = (*memoryBackend)(nil)
