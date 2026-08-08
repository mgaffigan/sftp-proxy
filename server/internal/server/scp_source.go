package server

// The sending half of SCP: `scp -f target`, which the client runs when it is
// downloading. Every file is announced with the exact number of bytes that
// follow it, so nothing can be sent until its length is known.

import (
	"errors"
	"fmt"
	"io"
	"path"

	"context"

	"sftp-proxy/internal/config"
	"sftp-proxy/internal/vfs"
)

// send runs a source session to completion.
func (s *scpSession) send(ctx context.Context, target string) error {
	// The client opens the exchange; nothing goes out before it is ready.
	if err := s.awaitAck(); err != nil {
		return err
	}
	node, err := s.fs.Stat(ctx, target)
	if err != nil {
		return s.fail(target, err)
	}
	return s.sendNode(ctx, target, node)
}

func (s *scpSession) sendNode(ctx context.Context, virtual string, node vfs.Node) error {
	if !node.IsDirectory() {
		return s.sendFile(ctx, virtual, node)
	}
	if !s.command.recursive {
		return s.fail(virtual, vfs.ErrUnsupported)
	}
	return s.sendDirectory(ctx, virtual, node)
}

// sendDirectory announces a directory, sends what is in it, and closes it. A
// child that cannot be sent is reported and skipped, leaving the rest of the
// tree to transfer and the session to end in failure.
func (s *scpSession) sendDirectory(ctx context.Context, virtual string, node vfs.Node) error {
	// The client names the directory it creates after this one, so a node with
	// no name of its own — only the root — cannot be sent as a tree.
	name := path.Base(virtual)
	if !config.ValidName(name) {
		return s.fail(virtual, vfs.ErrUnsupported)
	}

	listCtx, finish := s.startOperation(ctx, "list")
	children, err := s.fs.List(listCtx, virtual)
	finish(err)
	if err != nil {
		return s.fail(virtual, err)
	}

	if err := s.sendTimes(node); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(s.channel, "D%04o 0 %s\n", scpMode(node), name); err != nil {
		return err
	}
	if err := s.awaitAck(); err != nil {
		return err
	}

	for _, child := range children {
		if err := s.sendNode(ctx, path.Join(virtual, child.Name()), child); err != nil {
			return err
		}
	}

	if _, err := io.WriteString(s.channel, "E\n"); err != nil {
		return err
	}
	return s.awaitAck()
}

// sendFile announces one file and sends exactly the bytes it promised.
func (s *scpSession) sendFile(ctx context.Context, virtual string, node vfs.Node) error {
	ctx, finish := s.startOperation(ctx, "read")
	reader, err := s.fs.Open(ctx, virtual)
	if err != nil {
		finish(err)
		return s.fail(virtual, err)
	}
	defer reader.Close()

	// The length has to be known before the header goes out, and the reader's
	// answer is the only one worth having: it is the length of what is about to
	// be sent, rather than what something else said it would be.
	size, err := reader.Size()
	if err != nil {
		finish(err)
		return s.fail(virtual, err)
	}

	if err := s.sendTimes(node); err != nil {
		finish(err)
		return err
	}
	if _, err := fmt.Fprintf(s.channel, "C%04o %d %s\n", scpMode(node), size, node.Name()); err != nil {
		finish(err)
		return err
	}
	if err := s.awaitAck(); err != nil {
		finish(err)
		return err
	}

	if err := s.sendContents(reader, size); err != nil {
		finish(err)
		return err
	}
	if err := s.ack(); err != nil {
		finish(err)
		return err
	}
	finish(nil)
	return s.awaitAck()
}

// sendContents writes exactly size bytes. Coming up short is unrecoverable: the
// header has already promised that many, and the client counts them to find
// where the next control line begins.
func (s *scpSession) sendContents(reader vfs.ReaderAtCloser, size int64) error {
	buffer := make([]byte, transferBuffer)
	for offset := int64(0); offset < size; {
		window := min(int64(len(buffer)), size-offset)
		count, err := reader.ReadAt(buffer[:window], offset)
		if count > 0 {
			if _, writeErr := s.channel.Write(buffer[:count]); writeErr != nil {
				return writeErr
			}
			offset += int64(count)
		}
		switch {
		case int64(count) == window:
			// A full window, whether or not it also reported the end.
		case err == nil, errors.Is(err, io.EOF):
			// The file is shorter than its own size said it was.
			return errSCPProtocol
		default:
			return err
		}
	}
	return nil
}

// sendTimes states an entry's modification time, when the client asked for one
// and the entry has one to state. Access time is not something this filesystem
// keeps, so the modification time stands in for it.
func (s *scpSession) sendTimes(node vfs.Node) error {
	if !s.command.preserve || node.Mtime == nil {
		return nil
	}
	seconds := node.Mtime.Unix()
	if _, err := fmt.Fprintf(s.channel, "T%d 0 %d 0\n", seconds, seconds); err != nil {
		return err
	}
	return s.awaitAck()
}

// scpMode is the mode an entry is announced with. Like the SFTP file mode it
// states no policy: what a client may do is the backend's answer, not this.
func scpMode(node vfs.Node) uint32 {
	if node.Permissions != nil {
		return *node.Permissions
	}
	if node.IsDirectory() {
		return 0755
	}
	return 0644
}
