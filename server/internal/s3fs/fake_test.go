package s3fs

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// fakeS3 is a small object store speaking enough of the S3 API for this package
// to be exercised end to end: requests are really signed, really addressed
// path-style, and really answered with the XML and the ranges S3 would answer
// with, so what these tests drive is the same code path a bucket would.
type fakeS3 struct {
	bucket string

	mu       sync.Mutex
	objects  map[string][]byte
	metadata map[string]map[string]string
	// requests records what was asked of the store, and metadata what each
	// object was stored with: the x-amz-meta-* headers of the request that
	// wrote it, which is where a PutObject's user metadata arrives.
	requests  []string
	deny      bool
	broken    bool
	truncated bool
}

// modified is what every object here was last written at. A fixed instant makes
// a listing's metadata something a test can state rather than approximate.
var modified = time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)

func newFakeS3(bucket string) *fakeS3 {
	return &fakeS3{bucket: bucket, objects: make(map[string][]byte), metadata: make(map[string]map[string]string)}
}

func (f *fakeS3) put(key, contents string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[key] = []byte(contents)
}

func (f *fakeS3) get(key string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	contents, ok := f.objects[key]
	return string(contents), ok
}

// meta reports the user metadata an object was stored with.
func (f *fakeS3) meta(key string) map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.metadata[key]
}

func (f *fakeS3) keys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	names := make([]string, 0, len(f.objects))
	for key := range f.objects {
		names = append(names, key)
	}
	sort.Strings(names)
	return names
}

func (f *fakeS3) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

func (f *fakeS3) refuse() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deny = true
}

// breakDown answers everything with a failure that names no outcome of its own.
func (f *fakeS3) breakDown() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.broken = true
}

// truncateBodies promises a range and then sends less of it.
func (f *fakeS3) truncateBodies() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.truncated = true
}

func (f *fakeS3) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, request.Method+" "+request.URL.Path)
	denied, broken := f.deny, f.broken
	f.mu.Unlock()

	bucket, key, _ := strings.Cut(strings.TrimPrefix(request.URL.Path, "/"), "/")
	switch {
	case bucket != f.bucket:
		f.fail(writer, http.StatusNotFound, "NoSuchBucket")
	case broken:
		f.fail(writer, http.StatusNotImplemented, "NotImplemented")
	case denied:
		f.fail(writer, http.StatusForbidden, "AccessDenied")
	case request.Method == http.MethodGet && key == "":
		f.list(writer, request)
	case request.Method == http.MethodHead:
		f.head(writer, key)
	case request.Method == http.MethodGet:
		f.read(writer, request, key)
	case request.Method == http.MethodPut && request.Header.Get("x-amz-copy-source") != "":
		f.copy(writer, request, key)
	case request.Method == http.MethodPut:
		f.write(writer, request, key)
	case request.Method == http.MethodDelete:
		f.mu.Lock()
		delete(f.objects, key)
		f.mu.Unlock()
		writer.WriteHeader(http.StatusNoContent)
	default:
		f.fail(writer, http.StatusMethodNotAllowed, "MethodNotAllowed")
	}
}

func (f *fakeS3) list(writer http.ResponseWriter, request *http.Request) {
	prefix := request.URL.Query().Get("prefix")
	delimiter := request.URL.Query().Get("delimiter")

	f.mu.Lock()
	var contents, prefixes []string
	seen := make(map[string]bool)
	for key := range f.objects {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		rest := strings.TrimPrefix(key, prefix)
		if index := strings.Index(rest, delimiter); delimiter != "" && index >= 0 {
			if common := prefix + rest[:index+len(delimiter)]; !seen[common] {
				seen[common] = true
				prefixes = append(prefixes, common)
			}
			continue
		}
		contents = append(contents, key)
	}
	sort.Strings(contents)
	sort.Strings(prefixes)

	var body strings.Builder
	body.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	fmt.Fprintf(&body, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>%s</Name><Prefix>%s</Prefix><IsTruncated>false</IsTruncated><KeyCount>%d</KeyCount>`,
		escapeXML(f.bucket), escapeXML(prefix), len(contents)+len(prefixes))
	for _, key := range contents {
		fmt.Fprintf(&body, `<Contents><Key>%s</Key><Size>%d</Size><LastModified>%s</LastModified><StorageClass>STANDARD</StorageClass></Contents>`,
			escapeXML(key), len(f.objects[key]), modified.Format(time.RFC3339))
	}
	f.mu.Unlock()

	for _, common := range prefixes {
		fmt.Fprintf(&body, `<CommonPrefixes><Prefix>%s</Prefix></CommonPrefixes>`, escapeXML(common))
	}
	body.WriteString(`</ListBucketResult>`)

	writer.Header().Set("Content-Type", "application/xml")
	_, _ = io.WriteString(writer, body.String())
}

func (f *fakeS3) head(writer http.ResponseWriter, key string) {
	f.mu.Lock()
	contents, ok := f.objects[key]
	f.mu.Unlock()
	if !ok {
		// A HEAD carries no body, so a status is the whole of what S3 says.
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	writer.Header().Set("Content-Length", strconv.Itoa(len(contents)))
	writer.Header().Set("Last-Modified", modified.Format(http.TimeFormat))
	writer.WriteHeader(http.StatusOK)
}

func (f *fakeS3) read(writer http.ResponseWriter, request *http.Request, key string) {
	f.mu.Lock()
	contents, ok := f.objects[key]
	f.mu.Unlock()
	if !ok {
		f.fail(writer, http.StatusNotFound, "NoSuchKey")
		return
	}

	start, end := 0, len(contents)-1
	if header := request.Header.Get("Range"); header != "" {
		if _, err := fmt.Sscanf(header, "bytes=%d-%d", &start, &end); err != nil {
			f.fail(writer, http.StatusBadRequest, "InvalidRange")
			return
		}
		if start >= len(contents) {
			writer.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", len(contents)))
			f.fail(writer, http.StatusRequestedRangeNotSatisfiable, "InvalidRange")
			return
		}
		end = min(end, len(contents)-1)
		writer.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(contents)))
	}
	writer.Header().Set("Content-Length", strconv.Itoa(end-start+1))
	if request.Header.Get("Range") != "" {
		writer.WriteHeader(http.StatusPartialContent)
	}
	f.mu.Lock()
	truncated := f.truncated
	f.mu.Unlock()
	if truncated && end > start {
		end--
	}
	_, _ = writer.Write(contents[start : end+1])
}

func (f *fakeS3) write(writer http.ResponseWriter, request *http.Request, key string) {
	contents, err := io.ReadAll(request.Body)
	if err != nil {
		f.fail(writer, http.StatusInternalServerError, "InternalError")
		return
	}
	stored := map[string]string{}
	for name, values := range request.Header {
		if after, ok := strings.CutPrefix(strings.ToLower(name), "x-amz-meta-"); ok {
			stored[after] = values[0]
		}
	}
	f.mu.Lock()
	f.objects[key] = contents
	f.metadata[key] = stored
	f.mu.Unlock()
	writer.WriteHeader(http.StatusOK)
}

func (f *fakeS3) copy(writer http.ResponseWriter, request *http.Request, key string) {
	source, err := url.PathUnescape(request.Header.Get("x-amz-copy-source"))
	if err != nil {
		f.fail(writer, http.StatusBadRequest, "InvalidArgument")
		return
	}
	_, sourceKey, _ := strings.Cut(strings.TrimPrefix(source, "/"), "/")

	f.mu.Lock()
	contents, ok := f.objects[sourceKey]
	if ok {
		// No MetadataDirective means COPY, so the destination is stored with the
		// source's user metadata rather than the copy request's.
		f.objects[key] = contents
		f.metadata[key] = f.metadata[sourceKey]
	}
	f.mu.Unlock()
	if !ok {
		f.fail(writer, http.StatusNotFound, "NoSuchKey")
		return
	}
	writer.Header().Set("Content-Type", "application/xml")
	fmt.Fprintf(writer, `<?xml version="1.0" encoding="UTF-8"?><CopyObjectResult><LastModified>%s</LastModified><ETag>"copied"</ETag></CopyObjectResult>`,
		modified.Format(time.RFC3339))
}

// fail answers as S3 does, with a message naming everything a client must never
// be told: the bucket, the key, and the endpoint serving them.
func (f *fakeS3) fail(writer http.ResponseWriter, status int, code string) {
	writer.Header().Set("Content-Type", "application/xml")
	writer.WriteHeader(status)
	fmt.Fprintf(writer, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>%s on %s at object-store.example.invalid</Message><Resource>/%s/secret/key</Resource></Error>`,
		code, code, f.bucket, f.bucket)
}

func escapeXML(text string) string {
	var escaped strings.Builder
	_ = xml.EscapeText(&escaped, []byte(text))
	return escaped.String()
}
