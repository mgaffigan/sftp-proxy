// Package s3fs serves virtual filesystem nodes from S3 and S3-compatible object
// stores, named by s3:// URLs whose host is a bucket and whose path is an
// object key.
//
// A bucket is reached with credentials from one of two places. A deployment
// that knows its buckets when it starts lists them in its configuration file.
// A deployment that does not — a proxy fronting tenants it cannot enumerate —
// receives them on the entry that names the bucket, from the same backend that
// decided the user may see it at all; every child that entry leads to inherits
// them, so the credentials are stated once at the top of a subtree.
//
// Object stores have no directories, only keys that share a prefix. This
// package presents that as it is: a listing reports the prefixes it finds
// beneath a node, and there is no directory to create or remove because there
// was never one to begin with.
package s3fs

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"go.opentelemetry.io/otel/trace"

	"sftp-proxy/internal/config"
	"sftp-proxy/internal/headers"
	"sftp-proxy/internal/telemetry"
	"sftp-proxy/internal/vfs"
)

// uploadContentType is what an object uploaded over SFTP is stored as. The
// proxy is told nothing about a file's type, so claiming one would be a guess.
const uploadContentType = "application/octet-stream"

// maxSingleRequestSize is the largest object PutObject accepts and the largest
// CopyObject can move in one request. Beyond it S3 requires a multipart
// exchange, which this package does not do: a transfer that would need one is
// refused rather than half-performed.
const maxSingleRequestSize = 5 << 30

// allBits is every permission bit: the mask a node that states none imposes.
const allBits fs.FileMode = 0777

// maxListingEntries bounds one directory listing, as maxListingBytes bounds one
// served over HTTP. A prefix is not a directory and nothing limits how many keys
// share one, so without this a single ls could ask the proxy to hold millions of
// entries in memory. A listing that would exceed it fails rather than returning
// the first part of itself, which a client could not tell from the whole thing.
const maxListingEntries = 10000

type Backend struct {
	stagingDir string
	http       *http.Client
	// configured holds a client per bucket named in the configuration file.
	// A bucket absent from it is reachable only by an entry carrying its own
	// credentials.
	configured map[string]*s3.Client
}

// New prepares a client for every configured bucket. Credentials that must be
// discovered rather than stated are discovered here, so a deployment whose
// ambient identity is missing fails at startup rather than mid-transfer.
func New(backend *config.S3Backend, stagingDir string) (*Backend, error) {
	if backend == nil {
		return nil, errors.New("an s3 backend configuration is required")
	}
	instance := &Backend{
		stagingDir: stagingDir,
		http:       telemetry.NewHTTPClient(&http.Client{}),
		configured: make(map[string]*s3.Client, len(backend.Buckets)),
	}
	for _, bucket := range backend.Buckets {
		client, err := instance.configuredClient(bucket)
		if err != nil {
			return nil, fmt.Errorf("bucket %q: %w", bucket.Bucket, err)
		}
		instance.configured[bucket.Bucket] = client
	}
	return instance, nil
}

func (b *Backend) configuredClient(bucket config.S3Bucket) (*s3.Client, error) {
	if !bucket.UseDefaultCredentials {
		return b.client(bucket.S3Access), nil
	}
	// The proxy's own identity: environment, shared credentials file, web
	// identity token, or instance metadata, whichever the host provides. Only a
	// configuration file may ask for this, never an entry, so no backend can
	// direct the proxy to spend credentials it holds for itself.
	loaded, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion(bucket.Region),
		awsconfig.WithHTTPClient(b.http))
	if err != nil {
		return nil, err
	}
	return s3.NewFromConfig(loaded, clientOptions(bucket.S3Access)), nil
}

func (b *Backend) client(access config.S3Access) *s3.Client {
	return s3.NewFromConfig(aws.Config{
		Region:      access.Region,
		HTTPClient:  b.http,
		Credentials: credentials.NewStaticCredentialsProvider(access.AccessKeyID, access.SecretAccessKey, access.SessionToken),
	}, clientOptions(access))
}

func clientOptions(access config.S3Access) func(*s3.Options) {
	return func(options *s3.Options) {
		if access.Endpoint != "" {
			options.BaseEndpoint = aws.String(access.Endpoint)
		}
		options.UsePathStyle = access.UsePathStyle()
		// Uploads carry no checksum of their own beyond what an operation
		// requires. The SDK would otherwise add a trailing one, which some
		// S3-compatible services reject; nothing S3 depends on is withheld by
		// this, and MinIO accepts either. Responses are left to the SDK's
		// default, so a checksum a store does supply is still verified.
		options.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
	}
}

// location is where a node is: the client that can reach it, the bucket and key
// naming it, the permissions its mask allows, and the credentials to hand to
// everything found beneath it.
type location struct {
	client *s3.Client
	bucket string
	key    string
	mask   fs.FileMode
	access *config.S3Access
}

// resolve finds what serves a node. A node stating credentials is served with
// them; otherwise the configured bucket table is the only other authority, and
// a bucket in neither cannot be reached however an entry names it.
func (b *Backend) resolve(node vfs.Node) (location, error) {
	bucket, key, ok := config.S3Location(node.Backend)
	if !ok {
		return location{}, vfs.ErrFailure
	}
	at := location{bucket: bucket, key: key, mask: mask(node), access: node.S3}
	if node.S3 != nil {
		// Credentials that arrived with an entry are checked where they are
		// used, not only where they were parsed, since the entry may have come
		// from a backend listing rather than from a configuration file.
		if err := node.S3.Validate(); err != nil {
			return location{}, vfs.ErrFailure
		}
		at.client = b.client(*node.S3)
		return at, nil
	}
	client, configured := b.configured[bucket]
	if !configured {
		return location{}, vfs.ErrPermission
	}
	at.client = client
	return at, nil
}

// mask is what a node's permissions allow. An object store reports no modes of
// its own, so unlike a local file there is nothing to narrow: the node's value
// is the whole answer, and a listing states it again on every child, which is
// what makes a read-only directory a read-only subtree.
func mask(node vfs.Node) fs.FileMode {
	if node.Permissions == nil {
		return allBits
	}
	return fs.FileMode(*node.Permissions) & allBits
}

// readable and writable ask what a mode permits, as they do for a local file:
// any read bit permits reading and listing, any write bit permits every change,
// because the proxy is one actor rather than an owner, a group, and everyone
// else.
func readable(mode fs.FileMode) bool { return mode&0444 != 0 }
func writable(mode fs.FileMode) bool { return mode&0222 != 0 }

// prefix is the key every member of a directory node begins with. A bucket root
// has no key, and so no prefix at all.
func (l location) prefix() string {
	if l.key == "" {
		return ""
	}
	return l.key + "/"
}

// childURL names a member of this location. A name is a name whatever
// characters it contains, so it is escaped into the URL rather than pasted in.
func (l location) childURL(name string) string {
	return (&url.URL{Scheme: config.S3Scheme, Host: l.bucket, Path: "/" + l.prefix() + name}).String()
}

// sibling is this location with a different key in the same bucket, reached by
// the same client and governed by the same mask.
func (l location) sibling(key string) location {
	l.key = key
	return l
}

// head reports what the store knows about the object at this location.
func (l location) head(ctx context.Context) (*s3.HeadObjectOutput, error) {
	head, err := l.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(l.bucket),
		Key:    aws.String(l.key),
	})
	if err != nil {
		return nil, outcome(ctx, err)
	}
	return head, nil
}

// remove deletes the object at this location, which the store reports as
// success whether or not it was there.
func (l location) remove(ctx context.Context) error {
	_, err := l.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(l.bucket),
		Key:    aws.String(l.key),
	})
	return outcome(ctx, err)
}

func (b *Backend) List(ctx context.Context, node vfs.Node) ([]vfs.Node, error) {
	at, err := b.resolve(node)
	if err != nil {
		return nil, err
	}
	// A directory whose mask withholds reading is presented as empty, as one
	// served over HTTP that refuses GET is: it may still be a place to write to.
	if !readable(at.mask) {
		return nil, nil
	}

	prefix := at.prefix()
	pages := s3.NewListObjectsV2Paginator(at.client, &s3.ListObjectsV2Input{
		Bucket:    aws.String(at.bucket),
		Prefix:    aws.String(prefix),
		Delimiter: aws.String("/"),
	})
	var children []vfs.Node
	seen := make(map[string]bool)
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, outcome(ctx, err)
		}
		// Prefixes are taken first so that a key and a prefix sharing a name
		// resolve to the directory, which is the one of the two a client can
		// still descend into.
		for _, common := range page.CommonPrefixes {
			name := strings.TrimSuffix(strings.TrimPrefix(aws.ToString(common.Prefix), prefix), "/")
			if seen[name] || !config.ValidName(name) {
				continue
			}
			seen[name] = true
			children = append(children, at.childNode(vfs.Node{Directory: name}))
		}
		for _, object := range page.Contents {
			// A key equal to the prefix is the directory placeholder some tools
			// write. It names nothing within the directory, and ValidName is
			// what rejects it, along with any key a client could not ask for.
			name := strings.TrimPrefix(aws.ToString(object.Key), prefix)
			if seen[name] || !config.ValidName(name) {
				continue
			}
			seen[name] = true
			children = append(children, at.childNode(vfs.Node{
				File:  name,
				Size:  aws.ToInt64(object.Size),
				Mtime: object.LastModified,
			}))
		}
		if len(children) > maxListingEntries {
			trace.SpanFromContext(ctx).RecordError(fmt.Errorf(
				"listing exceeds %d entries", maxListingEntries))
			return nil, vfs.ErrFailure
		}
	}
	// A bucket lists in key order, which is not name order once a prefix has
	// been trimmed off. Sorting is what makes two listings of an unchanged
	// directory the same listing.
	slices.SortFunc(children, func(left, right vfs.Node) int {
		return strings.Compare(left.Name(), right.Name())
	})
	return children, nil
}

// childNode completes a member of this location: where it is, what may be done
// to it, and the credentials that reach it. The caller states the name and
// whatever the store reported about it; everything else follows from being
// found here.
func (l location) childNode(node vfs.Node) vfs.Node {
	permissions := uint32(l.mask)
	node.Backend = l.childURL(node.Name())
	node.Permissions = &permissions
	node.S3 = l.access
	return node
}

func (b *Backend) Open(ctx context.Context, node vfs.Node) (vfs.ReaderAtCloser, error) {
	at, err := b.resolve(node)
	if err != nil {
		return nil, err
	}
	if at.key == "" {
		return nil, vfs.ErrUnsupported
	}
	if !readable(at.mask) {
		return nil, vfs.ErrPermission
	}
	head, err := at.head(ctx)
	if err != nil {
		return nil, err
	}
	return &object{ctx: ctx, at: at, size: aws.ToInt64(head.ContentLength)}, nil
}

// Create stages the file locally and stores it whole on close. SFTP writes
// arrive at arbitrary offsets and an object is written in one request, so there
// is nothing to send until the client has finished saying what it is sending.
func (b *Backend) Create(ctx context.Context, node vfs.Node) (vfs.WriterAtCloser, error) {
	at, err := b.resolve(node)
	if err != nil {
		return nil, err
	}
	if at.key == "" {
		return nil, vfs.ErrUnsupported
	}
	if !writable(at.mask) {
		return nil, vfs.ErrPermission
	}
	return vfs.NewStagedWriter(b.stagingDir, func(contents *vfs.StagingFile) error {
		info, err := contents.Stat()
		if err != nil {
			return vfs.ErrFailure
		}
		if info.Size() > maxSingleRequestSize {
			return vfs.ErrUnsupported
		}
		_, err = at.client.PutObject(ctx, &s3.PutObjectInput{
			Bucket:        aws.String(at.bucket),
			Key:           aws.String(at.key),
			Body:          contents,
			ContentLength: aws.Int64(info.Size()),
			ContentType:   aws.String(uploadContentType),
			Metadata:      headers.From(ctx),
		})
		return outcome(ctx, err)
	})
}

// Mkdir has nothing to create. A directory here is the prefix its members
// share, so one with no members does not exist to be made, and a placeholder
// object standing in for it would be a file this proxy then had to hide.
func (b *Backend) Mkdir(context.Context, vfs.Node) error {
	return vfs.ErrUnsupported
}

// Remove deletes an object. A directory is refused for the same reason it
// cannot be created, and because emptying one is a walk rather than a request.
func (b *Backend) Remove(ctx context.Context, node vfs.Node) error {
	at, err := b.resolve(node)
	if err != nil {
		return err
	}
	if node.IsDirectory() || at.key == "" {
		return vfs.ErrUnsupported
	}
	if !writable(at.mask) {
		return vfs.ErrPermission
	}
	// Deleting a key that is not there succeeds, so asking first is what makes
	// removing something that has gone report that it has gone.
	if _, err := at.head(ctx); err != nil {
		return err
	}
	return at.remove(ctx)
}

// Rename moves an object within the directory it is already in, by copying it
// and deleting the original. Where a virtual path leads is the filesystem's
// knowledge rather than a backend's, so a destination anywhere else is refused
// rather than guessed at.
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
	if node.IsDirectory() || at.key == "" {
		return vfs.ErrUnsupported
	}
	if !writable(at.mask) {
		return vfs.ErrPermission
	}

	head, err := at.head(ctx)
	if err != nil {
		return err
	}
	if aws.ToInt64(head.ContentLength) > maxSingleRequestSize {
		return vfs.ErrUnsupported
	}
	target := name
	if directory := path.Dir(at.key); directory != "." {
		target = directory + "/" + name
	}
	// A copy replaces whatever key it is given, and SFTP says a rename that
	// would do so is an error rather than a replacement. Asking first is the
	// whole of what can be done about it: the store offers no conditional copy,
	// so an object arriving at the destination in between is still replaced.
	destination := at.sibling(target)
	switch _, err := destination.head(ctx); {
	case err == nil:
		return vfs.ErrExist
	case !errors.Is(err, vfs.ErrNotExist):
		return err
	}
	// MetadataDirective is omitted to keep the headers from PutObject intact.
	if _, err := at.client.CopyObject(ctx, &s3.CopyObjectInput{
		Bucket:     aws.String(at.bucket),
		Key:        aws.String(target),
		CopySource: aws.String(copySource(at.bucket, at.key)),
	}); err != nil {
		return outcome(ctx, err)
	}
	return at.remove(ctx)
}

// copySource names an object for the header that carries it, where the bucket
// and key are one escaped path rather than two fields.
func copySource(bucket, key string) string {
	source := url.URL{Path: "/" + bucket + "/" + key}
	return source.EscapedPath()
}

// Child names a member of a directory, whether or not it exists yet, by
// appending one escaped segment to the directory's key. It carries the mask in
// force on the directory, its credentials, and its upload limit, because a node
// that does not exist has none of its own.
func (b *Backend) Child(node vfs.Node, name string) (vfs.Node, error) {
	at, err := b.resolve(node)
	if err != nil {
		return vfs.Node{}, err
	}
	return at.childNode(vfs.Node{File: name, MaxUploadSize: node.MaxUploadSize}), nil
}

// outcome translates a failure into the outcome a caller may see. Nothing of
// the request travels with it: a bucket name, a key, an endpoint, or a remote
// message would otherwise reach an SFTP client. The cause goes on the span
// instead, where only the deployment can read it.
func outcome(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	var api smithy.APIError
	if errors.As(err, &api) {
		switch api.ErrorCode() {
		case "NoSuchKey", "NoSuchBucket", "NotFound":
			return vfs.ErrNotExist
		case "AccessDenied", "InvalidAccessKeyId", "SignatureDoesNotMatch", "ExpiredToken", "InvalidToken":
			return vfs.ErrPermission
		}
	}
	// A HeadObject failure carries no body to name an error code in, so the
	// status is all there is to go on.
	var response *smithyhttp.ResponseError
	if errors.As(err, &response) {
		switch response.HTTPStatusCode() {
		case http.StatusNotFound:
			return vfs.ErrNotExist
		case http.StatusUnauthorized, http.StatusForbidden:
			return vfs.ErrPermission
		}
	}
	trace.SpanFromContext(ctx).RecordError(err)
	return vfs.ErrFailure
}

var _ vfs.Backend = (*Backend)(nil)
