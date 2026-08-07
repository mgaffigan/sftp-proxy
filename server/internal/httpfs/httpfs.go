package httpfs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"

	"sftp-proxy/internal/config"
)

const directoryContentType = "application/vnd.sftproxy.directory+json"
const directoryEntryContentType = "application/vnd.sftpproxy.directoryentry"

type Filesystem struct {
	root       config.RootFS
	stagingDir string
	client     *http.Client
}

type resolvedEntry struct {
	entry   config.Entry
	allowed []string
}

func New(root config.RootFS, stagingDir string, client *http.Client) *Filesystem {
	return &Filesystem{root: root, stagingDir: stagingDir, client: client}
}

func (f *Filesystem) Handlers() sftp.Handlers {
	return sftp.Handlers{FileGet: f, FilePut: f, FileCmd: f, FileList: f}
}

func (f *Filesystem) Fileread(request *sftp.Request) (io.ReaderAt, error) {
	entry, err := f.resolve(request.Context(), request.Filepath)
	if err != nil {
		return nil, err
	}
	if entry.entry.File == "" {
		return nil, sftp.ErrSSHFxOpUnsupported
	}
	if !allows(entry.allowed, http.MethodGet) {
		return nil, sftp.ErrSSHFxOpUnsupported
	}
	return &rangeReader{ctx: request.Context(), fs: f, backendURL: entry.entry.Backend}, nil
}

func (f *Filesystem) Filewrite(request *sftp.Request) (io.WriterAt, error) {
	entry, err := f.resolveForWrite(request.Context(), request.Filepath)
	if err != nil {
		return nil, err
	}
	if entry.entry.File == "" || entry.entry.Backend == "" {
		return nil, sftp.ErrSSHFxOpUnsupported
	}
	if !allows(entry.allowed, http.MethodPost) {
		return nil, sftp.ErrSSHFxOpUnsupported
	}

	temporaryFile, err := os.CreateTemp(f.stagingDir, "upload-*")
	if err != nil {
		return nil, fmt.Errorf("create upload staging file: %w", err)
	}
	return &stagedUpload{
		ctx:        request.Context(),
		file:       temporaryFile,
		name:       temporaryFile.Name(),
		filesystem: f,
		backendURL: entry.entry.Backend,
	}, nil
}

func (f *Filesystem) Filecmd(request *sftp.Request) error {
	switch request.Method {
	case "Setstat":
		if _, err := f.resolve(request.Context(), request.Filepath); err != nil {
			return err
		}
		return nil
	case "Mkdir":
		if _, err := f.resolve(request.Context(), request.Filepath); err == nil {
			return sftp.ErrSSHFxFailure
		} else if !errors.Is(err, sftp.ErrSSHFxNoSuchFile) {
			return err
		}
		entry, err := f.resolveForWrite(request.Context(), request.Filepath)
		if err != nil {
			return err
		}
		if !allows(entry.allowed, http.MethodPost) {
			return sftp.ErrSSHFxOpUnsupported
		}
		return f.mutate(request.Context(), http.MethodPost, entry.entry.Backend, directoryEntryContentType, nil)
	case "Remove", "Rmdir":
		entry, err := f.resolve(request.Context(), request.Filepath)
		if err != nil {
			return err
		}
		if !allows(entry.allowed, http.MethodDelete) {
			return sftp.ErrSSHFxOpUnsupported
		}
		return f.mutate(request.Context(), http.MethodDelete, entry.entry.Backend, "", nil)
	case "Rename":
		entry, err := f.resolve(request.Context(), request.Filepath)
		if err != nil {
			return err
		}
		if !allows(entry.allowed, http.MethodDelete) {
			return sftp.ErrSSHFxOpUnsupported
		}
		target, err := virtualPathParts(request.Target)
		if err != nil || len(target) == 0 {
			return sftp.ErrSSHFxNoSuchFile
		}
		query := url.Values{"renameTo": []string{"/" + strings.Join(target, "/")}}
		parsed, err := url.Parse(entry.entry.Backend)
		if err != nil {
			return sftp.ErrSSHFxFailure
		}
		parsed.RawQuery = query.Encode()
		return f.mutate(request.Context(), http.MethodDelete, parsed.String(), "", nil)
	default:
		return sftp.ErrSSHFxOpUnsupported
	}
}

func (f *Filesystem) Filelist(request *sftp.Request) (sftp.ListerAt, error) {
	entry, err := f.resolve(request.Context(), request.Filepath)
	if err != nil {
		return nil, err
	}

	if request.Method == "Stat" {
		return lister{entries: []os.FileInfo{fileInfoFor(entry.entry)}}, nil
	}
	if request.Method != "List" {
		return nil, sftp.ErrSSHFxOpUnsupported
	}
	if entry.entry.File != "" {
		return nil, sftp.ErrSSHFxOpUnsupported
	}

	children, err := f.children(request.Context(), entry.entry)
	if err != nil {
		return nil, err
	}
	files := make([]os.FileInfo, 0, len(children))
	for _, child := range children {
		files = append(files, fileInfoFor(child))
	}
	return lister{entries: files}, nil
}

// resolve maps a virtual SFTP path onto the backend entry that serves it.
func (f *Filesystem) resolve(ctx context.Context, rawPath string) (resolvedEntry, error) {
	parts, err := virtualPathParts(rawPath)
	if err != nil {
		return resolvedEntry{}, sftp.ErrSSHFxNoSuchFile
	}
	root := f.root.Entry()
	if len(parts) == 0 {
		return resolvedEntry{entry: root, allowed: root.AllowedMethods}, nil
	}

	children, err := f.children(ctx, root)
	if err != nil {
		return resolvedEntry{}, err
	}
	for _, part := range parts[:len(parts)-1] {
		directory, err := findChild(children, part)
		if err != nil || directory.Directory == "" {
			return resolvedEntry{}, sftp.ErrSSHFxNoSuchFile
		}
		if children, err = f.children(ctx, directory); err != nil {
			return resolvedEntry{}, err
		}
	}

	entry, err := findChild(children, parts[len(parts)-1])
	if err != nil {
		return resolvedEntry{}, sftp.ErrSSHFxNoSuchFile
	}
	return resolvedEntry{entry: entry, allowed: entry.AllowedMethods}, nil
}

// resolveForWrite resolves a path that a create may bring into existence.
func (f *Filesystem) resolveForWrite(ctx context.Context, rawPath string) (resolvedEntry, error) {
	entry, err := f.resolve(ctx, rawPath)
	if err == nil {
		return entry, nil
	}
	if !errors.Is(err, sftp.ErrSSHFxNoSuchFile) {
		return resolvedEntry{}, err
	}

	parts, pathErr := virtualPathParts(rawPath)
	if pathErr != nil || len(parts) == 0 {
		return resolvedEntry{}, sftp.ErrSSHFxNoSuchFile
	}
	parentPath := "/" + strings.Join(parts[:len(parts)-1], "/")
	parent, err := f.resolve(ctx, parentPath)
	if err != nil || parent.entry.Directory == "" || parent.entry.Backend == "" {
		return resolvedEntry{}, sftp.ErrSSHFxNoSuchFile
	}
	backendURL, err := appendPathSegment(parent.entry.Backend, parts[len(parts)-1])
	if err != nil {
		return resolvedEntry{}, sftp.ErrSSHFxFailure
	}
	return resolvedEntry{
		entry:   config.Entry{File: parts[len(parts)-1], Backend: backendURL},
		allowed: parent.entry.AllowedMethods,
	}, nil
}

func (f *Filesystem) children(ctx context.Context, entry config.Entry) ([]config.Entry, error) {
	if !allows(entry.AllowedMethods, http.MethodGet) {
		return []config.Entry{}, nil
	}
	if entry.Backend == "" {
		return entry.Children, nil
	}

	response, err := f.do(ctx, http.MethodGet, entry.Backend, "", nil)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusMethodNotAllowed {
		return []config.Entry{}, nil
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, statusError(response.StatusCode)
	}
	contentType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || contentType != directoryContentType {
		return nil, sftp.ErrSSHFxFailure
	}

	decoder := json.NewDecoder(io.LimitReader(response.Body, 8<<20))
	decoder.DisallowUnknownFields()
	var listing struct {
		Children []config.Entry `json:"children"`
	}
	if err := decoder.Decode(&listing); err != nil {
		return nil, sftp.ErrSSHFxFailure
	}
	if err := config.ValidateEntries(listing.Children); err != nil {
		return nil, sftp.ErrSSHFxFailure
	}
	return listing.Children, nil
}

func (f *Filesystem) mutate(ctx context.Context, method, rawURL, contentType string, body io.Reader) error {
	response, err := f.do(ctx, method, rawURL, contentType, body)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return statusError(response.StatusCode)
	}
	return nil
}

func (f *Filesystem) do(ctx context.Context, method, rawURL, contentType string, body io.Reader) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, sftp.ErrSSHFxFailure
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}

	client := *f.client
	client.CheckRedirect = sameBackendRedirect(request.URL)
	response, err := client.Do(request)
	if err != nil {
		return nil, sftp.ErrSSHFxFailure
	}
	return response, nil
}

func sameBackendRedirect(origin *url.URL) func(*http.Request, []*http.Request) error {
	return func(request *http.Request, _ []*http.Request) error {
		if request.URL.Scheme != origin.Scheme || request.URL.Host != origin.Host || !pathHasPrefix(request.URL.Path, origin.Path) {
			return errors.New("redirect outside configured backend")
		}
		return nil
	}
}

func pathHasPrefix(candidate, prefix string) bool {
	prefix = strings.TrimSuffix(prefix, "/")
	return candidate == prefix || strings.HasPrefix(candidate, prefix+"/")
}

func virtualPathParts(rawPath string) ([]string, error) {
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

func findChild(children []config.Entry, name string) (config.Entry, error) {
	for _, child := range children {
		if child.Directory == name || child.File == name {
			return child, nil
		}
	}
	return config.Entry{}, os.ErrNotExist
}

func appendPathSegment(rawURL, name string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	parsed.Path = strings.TrimSuffix(parsed.Path, "/") + "/" + name
	return parsed.String(), nil
}

func statusError(status int) error {
	switch status {
	case http.StatusForbidden, http.StatusUnauthorized:
		return sftp.ErrSSHFxPermissionDenied
	case http.StatusNotFound:
		return sftp.ErrSSHFxNoSuchFile
	case http.StatusMethodNotAllowed:
		return sftp.ErrSSHFxOpUnsupported
	default:
		return sftp.ErrSSHFxFailure
	}
}

func allows(allowed []string, method string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, candidate := range allowed {
		if candidate == method {
			return true
		}
	}
	return false
}

type rangeReader struct {
	ctx        context.Context
	fs         *Filesystem
	backendURL string
	mu         sync.Mutex
	stagedFile *os.File
	stagedPath string
}

func (r *rangeReader) ReadAt(destination []byte, offset int64) (int, error) {
	if len(destination) == 0 {
		return 0, nil
	}

	r.mu.Lock()
	if r.stagedFile != nil {
		stagedFile := r.stagedFile
		r.mu.Unlock()
		return stagedFile.ReadAt(destination, offset)
	}

	request, err := http.NewRequestWithContext(r.ctx, http.MethodGet, r.backendURL, nil)
	if err != nil {
		r.mu.Unlock()
		return 0, sftp.ErrSSHFxFailure
	}
	request.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", offset, offset+int64(len(destination))-1))
	client := *r.fs.client
	client.CheckRedirect = sameBackendRedirect(request.URL)
	response, err := client.Do(request)
	if err != nil {
		r.mu.Unlock()
		return 0, sftp.ErrSSHFxFailure
	}

	if response.StatusCode == http.StatusRequestedRangeNotSatisfiable {
		_ = response.Body.Close()
		r.mu.Unlock()
		return 0, io.EOF
	}
	if response.StatusCode == http.StatusOK {
		stagedFile, err := os.CreateTemp(r.fs.stagingDir, "download-*")
		if err == nil {
			_, err = io.Copy(stagedFile, response.Body)
		}
		_ = response.Body.Close()
		if err != nil {
			if stagedFile != nil {
				_ = stagedFile.Close()
				_ = os.Remove(stagedFile.Name())
			}
			r.mu.Unlock()
			return 0, sftp.ErrSSHFxFailure
		}
		r.stagedFile = stagedFile
		r.stagedPath = stagedFile.Name()
		r.mu.Unlock()
		return stagedFile.ReadAt(destination, offset)
	}
	if response.StatusCode != http.StatusPartialContent {
		_ = response.Body.Close()
		r.mu.Unlock()
		if response.StatusCode >= http.StatusMultipleChoices {
			return 0, statusError(response.StatusCode)
		}
		return 0, sftp.ErrSSHFxFailure
	}
	r.mu.Unlock()
	defer response.Body.Close()
	count, err := io.ReadFull(response.Body, destination)
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return count, io.EOF
	}
	return count, err
}

func (r *rangeReader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stagedFile == nil {
		return nil
	}
	err := r.stagedFile.Close()
	removeErr := os.Remove(r.stagedPath)
	r.stagedFile = nil
	r.stagedPath = ""
	if err != nil {
		return err
	}
	return removeErr
}

type stagedUpload struct {
	ctx        context.Context
	file       *os.File
	name       string
	filesystem *Filesystem
	backendURL string
}

func (u *stagedUpload) WriteAt(data []byte, offset int64) (int, error) {
	return u.file.WriteAt(data, offset)
}

func (u *stagedUpload) Close() error {
	if err := u.file.Close(); err != nil {
		_ = os.Remove(u.name)
		return err
	}
	defer os.Remove(u.name)

	contents, err := os.Open(u.name)
	if err != nil {
		return err
	}
	defer contents.Close()
	return u.filesystem.mutate(u.ctx, http.MethodPost, u.backendURL, "application/octet-stream", contents)
}

type lister struct {
	entries []os.FileInfo
}

func (l lister) ListAt(target []os.FileInfo, offset int64) (int, error) {
	if offset >= int64(len(l.entries)) {
		return 0, io.EOF
	}
	count := copy(target, l.entries[offset:])
	if count < len(target) {
		return count, io.EOF
	}
	return count, nil
}

type fileInfo struct {
	name string
	size int64
	dir  bool
}

func fileInfoFor(entry config.Entry) fileInfo {
	return fileInfo{name: entryName(entry), size: entry.Size, dir: entry.Directory != ""}
}

func entryName(entry config.Entry) string {
	if entry.Directory != "" {
		return entry.Directory
	}
	return entry.File
}

func (f fileInfo) Name() string { return f.name }
func (f fileInfo) Size() int64  { return f.size }
func (f fileInfo) Mode() os.FileMode {
	if f.dir {
		return os.ModeDir | 0755
	}
	return 0644
}
func (f fileInfo) ModTime() time.Time { return time.Time{} }
func (f fileInfo) IsDir() bool        { return f.dir }
func (f fileInfo) Sys() any           { return nil }

var _ sftp.FileReader = (*Filesystem)(nil)
var _ sftp.FileWriter = (*Filesystem)(nil)
var _ sftp.FileCmder = (*Filesystem)(nil)
var _ sftp.FileLister = (*Filesystem)(nil)
var _ io.ReaderAt = (*rangeReader)(nil)
var _ io.Closer = (*rangeReader)(nil)
var _ io.WriterAt = (*stagedUpload)(nil)
var _ io.Closer = (*stagedUpload)(nil)
