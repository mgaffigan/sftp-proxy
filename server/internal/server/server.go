package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/crypto/ssh"

	"sftp-proxy/internal/auth"
	"sftp-proxy/internal/config"
	"sftp-proxy/internal/httpfs"
	"sftp-proxy/internal/localfs"
	"sftp-proxy/internal/telemetry"
	"sftp-proxy/internal/vfs"
)

type Server struct {
	config config.Config
	signer ssh.Signer
	auth   *auth.Authenticator
	local  *localfs.Backend
	logger *slog.Logger
}

func New(cfg config.Config, logger *slog.Logger) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate configuration: %w", err)
	}
	if logger == nil {
		logger = slog.Default()
	}
	privateKey, err := os.ReadFile(cfg.HostKeyFile)
	if err != nil {
		return nil, fmt.Errorf("read SSH host key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("parse SSH host key: %w", err)
	}

	server := &Server{config: cfg, signer: signer, auth: auth.New(cfg), logger: logger}
	if cfg.FileBackend != nil {
		if server.local, err = localfs.New(cfg.FileBackend.AllowedPrefixes); err != nil {
			return nil, fmt.Errorf("open file backend: %w", err)
		}
	}
	if err := os.MkdirAll(cfg.UploadStagingDir, 0700); err != nil {
		return nil, fmt.Errorf("create upload staging directory: %w", err)
	}
	return server, nil
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	listeners, err := s.listenAll()
	if err != nil {
		return err
	}
	defer func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	}()

	var waitGroup sync.WaitGroup
	for _, listener := range listeners {
		waitGroup.Go(func() {
			s.serveListener(ctx, listener)
		})
	}

	<-ctx.Done()
	for _, listener := range listeners {
		_ = listener.Close()
	}
	waitGroup.Wait()
	return nil
}

func (s *Server) listenAll() ([]net.Listener, error) {
	port := strconv.Itoa(s.config.Port)
	addresses := []struct {
		network string
		address string
	}{}
	if ip := net.ParseIP(s.config.BindAddress); ip != nil {
		network := "tcp6"
		if ip.To4() != nil {
			network = "tcp4"
		}
		addresses = append(addresses, struct {
			network string
			address string
		}{network: network, address: net.JoinHostPort(s.config.BindAddress, port)})
	} else if s.config.BindAddress != "" {
		addresses = append(addresses,
			struct {
				network string
				address string
			}{network: "tcp4", address: net.JoinHostPort(s.config.BindAddress, port)},
			struct {
				network string
				address string
			}{network: "tcp6", address: net.JoinHostPort(s.config.BindAddress, port)},
		)
	} else {
		addresses = append(addresses,
			struct {
				network string
				address string
			}{network: "tcp4", address: net.JoinHostPort("0.0.0.0", port)},
			struct {
				network string
				address string
			}{network: "tcp6", address: net.JoinHostPort("::", port)},
		)
	}

	listeners := make([]net.Listener, 0, len(addresses))
	for _, item := range addresses {
		listener, err := net.Listen(item.network, item.address)
		if err != nil {
			for _, existing := range listeners {
				_ = existing.Close()
			}
			return nil, fmt.Errorf("listen on %s %s: %w", item.network, item.address, err)
		}
		listeners = append(listeners, listener)
	}
	return listeners, nil
}

func (s *Server) serveListener(ctx context.Context, listener net.Listener) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			s.logger.Error("accept SSH connection", "error", err)
			continue
		}
		go s.serveConnection(ctx, connection)
	}
}

func (s *Server) serveConnection(ctx context.Context, connection net.Conn) {
	defer connection.Close()
	connectionCtx, span := telemetry.Tracer().Start(ctx, "ssh.connection", trace.WithAttributes(connectionAttributes(connection.RemoteAddr())...))
	defer span.End()
	// Bound the handshake: a client that opens a socket and then goes silent
	// must not hold this goroutine, and the auth callbacks it drives, forever.
	// This is pre-authentication, so the limit can only come from the server
	// config — there is no user to consult yet.
	loginGrace := s.config.LoginGrace()
	if loginGrace > 0 {
		if err := connection.SetDeadline(time.Now().Add(loginGrace)); err != nil {
			s.logger.Error("set login grace deadline", "remote", connection.RemoteAddr(), "error", err)
			return
		}
	}

	authConn := s.auth.NewConn(connectionCtx)
	sshConfig := &ssh.ServerConfig{
		PasswordCallback:  authConn.Password,
		PublicKeyCallback: authConn.PublicKey,
	}
	sshConfig.AddHostKey(s.signer)

	sshConnection, channels, requests, err := ssh.NewServerConn(connection, sshConfig)
	if err != nil {
		span.SetStatus(codes.Error, "SSH connection rejected")
		span.SetAttributes(attribute.String("error.type", "ssh_rejected"))
		s.logger.Info("reject SSH connection", "remote", connection.RemoteAddr(), "error", err)
		return
	}
	defer sshConnection.Close()
	span.SetAttributes(attribute.String("user.name", sshConnection.User()))
	// The grace period covers authentication only. Past it liveness is the
	// authenticated user's ClientAlive policy, which tolerates the long quiet
	// stretches an SFTP transfer can produce.
	if err := connection.SetDeadline(time.Time{}); err != nil {
		s.logger.Error("clear login grace deadline", "remote", connection.RemoteAddr(), "error", err)
		return
	}
	session, ok := auth.SessionFrom(sshConnection.Permissions)
	if !ok {
		s.logger.Error("authenticated session has no user configuration", "user", sshConnection.User())
		return
	}

	s.logger.Info("accept SSH connection", "user", sshConnection.User(), "remote", sshConnection.RemoteAddr())
	go ssh.DiscardRequests(requests)

	// One filesystem per connection, shared by every channel on it. It carries
	// the resolution cache, so it must outlive a single channel, and it uses
	// the connection's cookie jar by way of session.Client.
	filesystem := s.filesystem(session)
	requestHandlerFactory := newHandlerFactory(filesystem, session.User.UploadConcurrencyLimit())

	done := make(chan struct{})
	defer close(done)
	go s.clientAlive(sshConnection, session.User, done)

	for newChannel := range channels {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "only session channels are supported")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			s.logger.Debug("accept SSH channel", "error", err)
			continue
		}
		go s.serveSession(connectionCtx, session.User.Username, sshConnection.RemoteAddr(), channel, requests, requestHandlerFactory)
	}
}

func connectionAttributes(address net.Addr) []attribute.KeyValue {
	tcpAddress, ok := address.(*net.TCPAddr)
	if !ok {
		return nil
	}
	return []attribute.KeyValue{
		attribute.String("client.address", tcpAddress.IP.String()),
		attribute.Int("client.port", tcpAddress.Port),
	}
}

// filesystem assembles the user's virtual filesystem and the backends allowed
// to serve it. A URL scheme absent from this registry cannot be reached,
// whether it was configured or arrived in a backend's directory listing.
func (s *Server) filesystem(session auth.Session) *vfs.FS {
	overHTTP := httpfs.New(session.Client, s.config.UploadStagingDir)
	backends := vfs.Backends{
		"http":  overHTTP,
		"https": overHTTP,
	}
	// The local backend holds the directories a deployment consented to serve,
	// which belong to the process rather than to one connection: it has no
	// cookie jar to carry and no per-session state at all.
	if s.local != nil {
		backends[config.FileScheme] = s.local
	}
	return vfs.New(session.User.RootFS, backends)
}

// clientAlive implements the user's clientAliveMs and clientAliveCountMax:
// after interval with no answer it probes the client, and closes the
// connection once countMax consecutive probes go unanswered. Closing
// ends the channel loop in serveConnection, which closes done and stops us.
//
// The probe is sent from a goroutine because SendRequest blocks until the peer
// replies, which is exactly what a wedged client will never do. At most
// countMax such goroutines can be outstanding, and they all unblock when the
// connection closes.
func (s *Server) clientAlive(connection *ssh.ServerConn, user config.User, done <-chan struct{}) {
	interval, countMax := user.ClientAlive()
	if interval <= 0 || countMax <= 0 {
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	unanswered := 0
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
		}

		answered := make(chan error, 1)
		go func() {
			_, _, err := connection.SendRequest("keepalive@openssh.com", true, nil)
			answered <- err
		}()

		select {
		case <-done:
			return
		case err := <-answered:
			if err != nil {
				return // The connection is already gone; serveConnection cleans up.
			}
			unanswered = 0
		case <-time.After(interval):
			unanswered++
			if unanswered < countMax {
				continue
			}
			s.logger.Info("disconnect unresponsive client",
				"user", connection.User(), "remote", connection.RemoteAddr(), "probes", unanswered)
			_ = connection.Close()
			return
		}
	}
}

// serveSession runs the one thing a session channel is asked to do. A client
// arrives speaking either SFTP, over a subsystem request, or SCP, over an exec
// request; nothing else is run here, and asking for anything else is refused
// rather than answered with a failing command.
func (s *Server) serveSession(ctx context.Context, username string, remoteAddress net.Addr, channel ssh.Channel, requests <-chan *ssh.Request, requestHandlerFactory *handlerFactory) {
	defer channel.Close()
	attributes := append([]attribute.KeyValue{attribute.String("user.name", username)}, connectionAttributes(remoteAddress)...)

	for request := range requests {
		switch request.Type {
		case "subsystem":
			var payload struct{ Name string }
			if err := ssh.Unmarshal(request.Payload, &payload); err != nil || payload.Name != "sftp" {
				_ = request.Reply(false, nil)
				continue
			}
			if err := request.Reply(true, nil); err != nil {
				return
			}
			s.serveSFTP(ctx, attributes, channel, requestHandlerFactory)
			return

		case "exec":
			var payload struct{ Command string }
			command, ok := scpCommand{}, false
			if err := ssh.Unmarshal(request.Payload, &payload); err == nil {
				command, ok = parseSCPCommand(payload.Command)
			}
			if !ok {
				_ = request.Reply(false, nil)
				continue
			}
			if err := request.Reply(true, nil); err != nil {
				return
			}
			s.serveSCP(ctx, attributes, channel, requestHandlerFactory, command)
			return

		default:
			_ = request.Reply(false, nil)
		}
	}
}

func (s *Server) serveSFTP(ctx context.Context, attributes []attribute.KeyValue, channel ssh.Channel, requestHandlerFactory *handlerFactory) {
	sessionCtx, span := telemetry.Tracer().Start(ctx, "sftp.session", trace.WithAttributes(attributes...))
	defer span.End()

	requestServer := sftp.NewRequestServer(channel, requestHandlerFactory.handlers(sessionCtx))
	if err := requestServer.Serve(); err != nil && !errors.Is(err, io.EOF) {
		span.SetStatus(codes.Error, "serve SFTP session")
		span.SetAttributes(attribute.String("error.type", "sftp"))
		s.logger.Debug("serve SFTP request", "error", err)
	}
}

// serveSCP runs one SCP transfer and reports how it went as the exit status of
// the command the client believes it ran. A client that is told nothing waits
// for a status that never comes, so this is sent on every path.
func (s *Server) serveSCP(ctx context.Context, attributes []attribute.KeyValue, channel ssh.Channel, requestHandlerFactory *handlerFactory, command scpCommand) {
	sessionCtx, span := telemetry.Tracer().Start(ctx, "scp.session", trace.WithAttributes(attributes...))
	defer span.End()

	var status uint32
	if !requestHandlerFactory.scp(command, channel).run(sessionCtx) {
		status = 1
		span.SetStatus(codes.Error, "serve SCP session")
		span.SetAttributes(attribute.String("error.type", "scp"))
	}
	_ = channel.CloseWrite()
	_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: status}))
}
