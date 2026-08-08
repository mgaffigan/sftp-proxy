package s3fs

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"sftp-proxy/internal/vfs"
)

// object reads one S3 object, one range request per read.
//
// There is none of the negotiation an HTTP backend needs. S3 states an object's
// exact length before a byte is transferred and answers every range request
// with the range asked for, so the length is known from the start, a read past
// the end is answered without a request, and nothing is ever staged on disk to
// discover how long something was.
//
// The context is held rather than passed because io.ReaderAt cannot take one.
// It is the context of the operation that opened the file.
type object struct {
	ctx  context.Context
	at   location
	size int64
}

func (o *object) ReadAt(destination []byte, offset int64) (int, error) {
	if offset < 0 {
		return 0, vfs.ErrFailure
	}
	if offset >= o.size {
		return 0, io.EOF
	}
	if len(destination) == 0 {
		return 0, nil
	}
	// The request asks only for bytes that exist, so a short read is the object
	// ending early rather than the range being clamped.
	length := min(int64(len(destination)), o.size-offset)

	response, err := o.at.client.GetObject(o.ctx, &s3.GetObjectInput{
		Bucket: aws.String(o.at.bucket),
		Key:    aws.String(o.at.key),
		Range:  aws.String(fmt.Sprintf("bytes=%d-%d", offset, offset+length-1)),
	})
	if err != nil {
		return 0, outcome(o.ctx, err)
	}
	defer response.Body.Close()

	count, err := io.ReadFull(response.Body, destination[:length])
	switch {
	case errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF):
		return count, io.EOF
	case err != nil:
		return count, outcome(o.ctx, err)
	case count < len(destination):
		// The caller asked past the end of the object, which is where it ends.
		return count, io.EOF
	}
	return count, nil
}

func (o *object) Size() (int64, error) { return o.size, nil }

// Close has nothing to release: every read opened and closed its own response.
func (o *object) Close() error { return nil }

var _ vfs.ReaderAtCloser = (*object)(nil)
