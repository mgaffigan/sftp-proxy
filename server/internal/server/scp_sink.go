package server

// The receiving half of SCP: `scp -t target`, which the client runs when it is
// uploading. The client sends control lines describing what it is about to
// send, and this side answers each with an acknowledgement or a refusal.

import (
	"context"
	"errors"
	"io"
	"path"
	"strconv"
	"strings"

	"sftp-proxy/internal/config"
	"sftp-proxy/internal/vfs"
)

// scpTarget is where the next entry lands. A client uploading into a directory
// names each entry itself; one uploading a single file to a path that is not a
// directory has already named it, which is what `scp a.txt host:b.txt` means.
type scpTarget struct {
	path  string
	named bool
}

// resolve gives the path an entry called name should be written to.
func (t scpTarget) resolve(name string) string {
	if !t.named {
		return t.path
	}
	return path.Join(t.path, name)
}

// receive runs a sink session to completion. The stream ends when the client
// closes it, which is the ordinary way an upload finishes.
func (s *scpSession) receive(ctx context.Context, target string) error {
	// Where entries land is settled once, before anything is read: a target
	// that is a directory takes entries by their own names, and one that is not
	// is itself the name. -d says the client will only accept the former.
	node, err := s.fs.Stat(ctx, target)
	targetIsDirectory := err == nil && node.IsDirectory()
	switch {
	case s.command.directory && !targetIsDirectory:
		return vfs.ErrNotExist
	case err != nil && !errors.Is(err, vfs.ErrNotExist):
		return err
	}

	stack := []scpTarget{{path: target, named: targetIsDirectory}}
	if err := s.ack(); err != nil {
		return err
	}
	for {
		line, err := s.readLine()
		if errors.Is(err, io.EOF) {
			// The client has nothing further to send.
			return nil
		}
		if err != nil {
			return err
		}
		if len(line) == 0 {
			return errSCPProtocol
		}

		switch line[0] {
		case 'C':
			if err := s.receiveFile(ctx, stack[len(stack)-1], line); err != nil {
				return err
			}
		case 'D':
			next, err := s.receiveDirectory(ctx, stack[len(stack)-1], line)
			if err != nil {
				return err
			}
			stack = append(stack, next)
		case 'E':
			// The outermost frame is the target itself, which the client never
			// opened and so cannot close.
			if len(stack) == 1 {
				return errSCPProtocol
			}
			stack = stack[:len(stack)-1]
			if err := s.ack(); err != nil {
				return err
			}
		case 'T':
			// Modification times, which are a synthetic no-op here for the same
			// reason a setstat is. Accepted so the client may go on.
			if err := s.ack(); err != nil {
				return err
			}
		default:
			return errSCPProtocol
		}
	}
}

// receiveFile takes one `Cmmmm <size> <name>` and the bytes that follow it.
//
// A file this side will not take is refused in place of the acknowledgement,
// and the client then skips sending it — which is the only reason the stream
// stays interpretable after a failure.
func (s *scpSession) receiveFile(ctx context.Context, target scpTarget, header string) error {
	ctx, finish := s.startOperation(ctx, "write")
	size, name, err := parseSCPFileHeader(header)
	if err != nil {
		finish(err)
		return err
	}
	destination := target.resolve(name)

	release, ok := s.uploads.acquire()
	if !ok {
		finish(vfs.ErrFailure)
		return s.fail(destination, vfs.ErrFailure)
	}
	defer release()

	writer, err := s.fs.Create(ctx, destination)
	if err != nil {
		finish(err)
		return s.fail(destination, err)
	}
	if err := s.ack(); err != nil {
		_ = writer.Abort()
		finish(err)
		return err
	}

	// SCP sends a file start to end, so the offsets an io.WriterAt wants are
	// just how far along the stream is.
	contentsErr := s.receiveContents(io.NewOffsetWriter(writer, 0), size)
	if errors.Is(contentsErr, errSCPProtocol) {
		// The client stopped mid-file: nothing can be resynchronised.
		_ = writer.Abort()
		finish(contentsErr)
		return contentsErr
	}

	// The client's own verdict on the file it just sent. It having gone wrong at
	// that end makes the staged copy worthless at this one.
	status, err := s.readByte()
	if err != nil {
		_ = writer.Abort()
		finish(err)
		return err
	}
	if status != scpOK {
		_, _ = s.readLine()
		_ = writer.Abort()
		finish(errSCPRefused)
		return errSCPRefused
	}

	if contentsErr != nil {
		_ = writer.Abort()
		finish(contentsErr)
		return s.fail(destination, contentsErr)
	}
	if err := writer.Close(); err != nil {
		finish(err)
		return s.fail(destination, err)
	}
	finish(nil)
	return s.ack()
}

// receiveDirectory takes one `Dmmmm 0 <name>` and returns the target its
// contents land in. A directory that is already there is what the client
// wanted, so it is not an error.
//
// One that could not be made is, and is still returned: the client sends that
// directory's contents and its matching E either way, so the frame has to be
// there to be closed. What goes into a directory that is not there is refused
// an entry at a time, which leaves the stream readable.
func (s *scpSession) receiveDirectory(ctx context.Context, target scpTarget, header string) (scpTarget, error) {
	ctx, finish := s.startOperation(ctx, "mkdir")
	_, name, err := parseSCPFileHeader(header)
	if err != nil {
		finish(err)
		return scpTarget{}, err
	}
	destination := target.resolve(name)
	contents := scpTarget{path: destination, named: true}

	err = s.fs.Mkdir(ctx, destination)
	finish(err)
	if err != nil && !errors.Is(err, vfs.ErrExist) {
		return contents, s.fail(destination, err)
	}
	return contents, s.ack()
}

// receiveContents copies size bytes from the client into writer.
//
// All size of them are read whatever happens to them, because the client is
// sending them regardless and what follows them is the next control line. A
// write that fails therefore stops the writing and not the reading, and is
// reported once the stream is back where it should be.
func (s *scpSession) receiveContents(writer io.Writer, size int64) error {
	buffer := make([]byte, transferBuffer)
	var failure error
	for remaining := size; remaining > 0; {
		window := min(int64(len(buffer)), remaining)
		count, err := io.ReadFull(s.channel, buffer[:window])
		remaining -= int64(count)
		if failure == nil && count > 0 {
			if _, writeErr := writer.Write(buffer[:count]); writeErr != nil {
				failure = vfs.ErrFailure
			}
		}
		if err != nil {
			return errSCPProtocol
		}
	}
	return failure
}

// parseSCPFileHeader reads a C or D line: a mode, a size, and a name. Only the
// last two are used — permissions are a synthetic no-op here, as they are over
// SFTP — and the name is checked rather than trusted, since a client naming its
// own destination is otherwise a way to write outside the target directory.
func parseSCPFileHeader(header string) (int64, string, error) {
	_, remainder, ok := strings.Cut(header[1:], " ")
	if !ok {
		return 0, "", errSCPProtocol
	}
	// The name is whatever is left, so that a name containing spaces survives.
	sizeText, name, ok := strings.Cut(remainder, " ")
	if !ok || !config.ValidName(name) {
		return 0, "", errSCPProtocol
	}
	size, err := strconv.ParseInt(sizeText, 10, 64)
	if err != nil || size < 0 {
		return 0, "", errSCPProtocol
	}
	return size, name, nil
}
