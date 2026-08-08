package server

// SCP is the other protocol a client may arrive speaking. It comes in over an
// exec channel — the client runs `scp -t dir` or `scp -f file` — and the two
// sides then take turns, each waiting for one acknowledgement byte before going
// on. There is no request to fail, so a problem is either said in the protocol's
// own terms and the transfer continues, or it cannot be and the transfer ends.
//
// scp.go holds what both directions need: the command, the paths, the turn
// taking. scp_sink.go receives, scp_source.go sends.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"sftp-proxy/internal/telemetry"
	"sftp-proxy/internal/vfs"
)

// The bytes the protocol turns on: 0 accepts, 1 reports a problem the transfer
// can continue past, 2 reports one it cannot. A message follows the latter two.
const (
	scpOK      = 0
	scpWarning = 1
	scpFatal   = 2
)

// maxSCPLine bounds one control line. Lines are short by construction, so the
// limit exists only so that a client which never sends a newline cannot be
// answered with unbounded memory.
const maxSCPLine = 4096

// transferBuffer is the window a file is copied through, in either direction.
const transferBuffer = 32 << 10

var (
	errSCPProtocol = errors.New("protocol error")
	errSCPRefused  = errors.New("client refused the transfer")
)

// scpCommand is an exec request that turned out to be scp.
type scpCommand struct {
	sink      bool   // -t: the client sends and we receive
	source    bool   // -f: the client receives and we send
	recursive bool   // -r
	preserve  bool   // -p: carry modification times
	directory bool   // -d: the operand must name a directory
	path      string // the single operand, as the client wrote it
}

// scpChannel is what a session needs of its SSH channel: the stream the protocol
// runs over, and somewhere to put what is not part of it. Narrowed to this so
// the protocol can be driven over a pipe.
type scpChannel interface {
	io.ReadWriter
	Stderr() io.ReadWriter
}

type scpSession struct {
	command scpCommand
	fs      *vfs.FS
	uploads *uploadLimiter
	channel scpChannel
	// refused records that some path was reported as a problem. The transfer
	// carries on past one, but the session did not do all it was asked and its
	// exit status has to say so.
	refused bool
}

func (f *handlerFactory) scp(command scpCommand, channel scpChannel) *scpSession {
	return &scpSession{command: command, fs: f.fs, uploads: f.uploads, channel: channel}
}

// run carries out the transfer and reports whether it succeeded, which is the
// exit status the client is waiting on.
func (s *scpSession) run(ctx context.Context) bool {
	target, err := virtualPath(s.command.path)
	if err == nil {
		if s.command.sink {
			err = s.receive(ctx, target)
		} else {
			err = s.send(ctx, target)
		}
	}
	if err == nil {
		return !s.refused
	}
	// The stream is no longer interpretable, so this is the last thing said about
	// it, and it says an outcome rather than a cause.
	fmt.Fprintf(s.channel.Stderr(), "scp: %s\n", scpError(err))
	return false
}

// ack accepts what the client last sent.
func (s *scpSession) ack() error {
	_, err := s.channel.Write([]byte{scpOK})
	return err
}

// fail reports a problem with one path and lets the transfer go on. The message
// reaches the client, so it names the virtual path and the outcome, never which
// backend was asked or what it answered.
func (s *scpSession) fail(virtual string, cause error) error {
	s.refused = true
	_, err := fmt.Fprintf(s.channel, "%cscp: %s: %s\n", scpWarning, virtual, scpError(cause))
	return err
}

// awaitAck reads the client's answer to something we sent. A client that
// answers with a problem of its own has ended the transfer.
func (s *scpSession) awaitAck() error {
	status, err := s.readByte()
	if err != nil {
		return err
	}
	switch status {
	case scpOK:
		return nil
	case scpWarning, scpFatal:
		_, _ = s.readLine() // the client's own message, which it already knows
		return errSCPRefused
	default:
		return errSCPProtocol
	}
}

// scpError reduces an outcome to something a client may be shown, for the reason
// statusError does it: an unrecognised error's own text travels as it is, and
// could name a backend.
func scpError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, vfs.ErrNotExist):
		return vfs.ErrNotExist
	case errors.Is(err, vfs.ErrPermission):
		return vfs.ErrPermission
	case errors.Is(err, vfs.ErrUnsupported):
		return vfs.ErrUnsupported
	case errors.Is(err, vfs.ErrExist):
		return vfs.ErrExist
	case errors.Is(err, errSCPProtocol):
		return errSCPProtocol
	case errors.Is(err, errSCPRefused):
		return errSCPRefused
	default:
		return vfs.ErrFailure
	}
}

func (s *scpSession) readByte() (byte, error) {
	var buffer [1]byte
	if _, err := io.ReadFull(s.channel, buffer[:]); err != nil {
		return 0, err
	}
	return buffer[0], nil
}

// readLine reads one control line, without its newline. It reads a byte at a
// time because the bytes after a line may be file contents, which must be left
// where they are rather than buffered ahead.
func (s *scpSession) readLine() (string, error) {
	var line strings.Builder
	for {
		character, err := s.readByte()
		if err != nil {
			return "", err
		}
		if character == '\n' {
			return line.String(), nil
		}
		if line.Len() >= maxSCPLine {
			return "", errSCPProtocol
		}
		line.WriteByte(character)
	}
}

func (s *scpSession) startOperation(ctx context.Context, operation string) (context.Context, func(error)) {
	ctx, span := telemetry.Tracer().Start(ctx, "scp."+operation,
		trace.WithAttributes(attribute.String("scp.operation", operation)))
	var once sync.Once
	return ctx, func(err error) {
		once.Do(func() {
			recordOperationError(span, err)
			span.End()
		})
	}
}

// parseSCPCommand reads an exec request as the scp invocation it claims to be,
// reporting whether it is one. Anything else is not something this server runs.
func parseSCPCommand(command string) (scpCommand, bool) {
	tokens, ok := shellSplit(command)
	if !ok || len(tokens) == 0 {
		return scpCommand{}, false
	}
	if name := tokens[0]; name != "scp" && !strings.HasSuffix(name, "/scp") {
		return scpCommand{}, false
	}

	var parsed scpCommand
	var operands []string
	flagsEnded := false
	for _, token := range tokens[1:] {
		switch {
		case flagsEnded, !strings.HasPrefix(token, "-"), token == "-":
			operands = append(operands, token)
			continue
		case token == "--":
			flagsEnded = true
			continue
		}
		for _, flag := range token[1:] {
			switch flag {
			case 't':
				parsed.sink = true
			case 'f':
				parsed.source = true
			case 'r':
				parsed.recursive = true
			case 'p':
				parsed.preserve = true
			case 'd':
				parsed.directory = true
			case 'v', 'q':
				// How loudly the client narrates its own end is its business.
			default:
				return scpCommand{}, false
			}
		}
	}

	// Exactly one direction, and exactly one thing to transfer. Both flags or
	// neither is not an invocation scp itself would ever make.
	if parsed.sink == parsed.source || len(operands) != 1 {
		return scpCommand{}, false
	}
	parsed.path = operands[0]
	return parsed, true
}

// shellSplit undoes the quoting an scp client applied to its own arguments.
// sshd hands an exec command to a login shell, so clients quote paths expecting
// one to be there; there is no shell here, and the quoting still has to come
// off somewhere. Nothing is ever executed, so this only has to reverse quoting,
// not decide what is safe to run.
func shellSplit(command string) ([]string, bool) {
	var tokens []string
	var current strings.Builder
	started := false

	runes := []rune(command)
	for index := 0; index < len(runes); index++ {
		character := runes[index]
		switch {
		case character == ' ' || character == '\t' || character == '\n':
			if started {
				tokens = append(tokens, current.String())
				current.Reset()
				started = false
			}
		case character == '\'':
			// Single quotes are literal all the way to the closing quote.
			started = true
			index++
			for ; index < len(runes) && runes[index] != '\''; index++ {
				current.WriteRune(runes[index])
			}
			if index == len(runes) {
				return nil, false
			}
		case character == '"':
			started = true
			index++
			for ; index < len(runes) && runes[index] != '"'; index++ {
				if runes[index] == '\\' && index+1 < len(runes) && strings.ContainsRune("\"\\$`", runes[index+1]) {
					index++
				}
				current.WriteRune(runes[index])
			}
			if index == len(runes) {
				return nil, false
			}
		case character == '\\':
			if index+1 == len(runes) {
				return nil, false
			}
			index++
			started = true
			current.WriteRune(runes[index])
		default:
			started = true
			current.WriteRune(character)
		}
	}
	if started {
		tokens = append(tokens, current.String())
	}
	return tokens, true
}

// virtualPath maps a path as an scp client wrote it onto a virtual filesystem
// path. Clients write paths relative to a home directory and abbreviate that
// directory as ~; here it is the root, there being nowhere else to be.
//
// Cleaning collapses . and .. against the root, which is where traversal past
// the top of a filesystem ends up on a real server too.
func virtualPath(raw string) (string, error) {
	if strings.ContainsRune(raw, 0) {
		return "", vfs.ErrNotExist
	}
	switch {
	case raw == "", raw == "~":
		raw = "/"
	case strings.HasPrefix(raw, "~/"):
		raw = raw[1:]
	case strings.HasPrefix(raw, "~"):
		// ~someone names a home directory this server has no notion of.
		return "", vfs.ErrNotExist
	}
	if !strings.HasPrefix(raw, "/") {
		raw = "/" + raw
	}
	return path.Clean(raw), nil
}
