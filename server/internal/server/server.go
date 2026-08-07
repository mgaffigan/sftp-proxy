package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"sftp-proxy/internal/auth"
	"sftp-proxy/internal/config"
	"sftp-proxy/internal/httpfs"
)

type Server struct {
	config config.Config
	signer ssh.Signer
	auth   *auth.Authenticator
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
			s.serveListener(listener)
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
	addresses := []struct {
		network string
		address string
	}{
		{network: "tcp4", address: fmt.Sprintf("0.0.0.0:%d", s.config.Port)},
		{network: "tcp6", address: fmt.Sprintf("[::]:%d", s.config.Port)},
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

func (s *Server) serveListener(listener net.Listener) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			s.logger.Error("accept SSH connection", "error", err)
			continue
		}
		go s.serveConnection(connection)
	}
}

func (s *Server) serveConnection(connection net.Conn) {
	defer connection.Close()
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

	authConn := s.auth.NewConn()
	sshConfig := &ssh.ServerConfig{
		PasswordCallback:  authConn.Password,
		PublicKeyCallback: authConn.PublicKey,
	}
	sshConfig.AddHostKey(s.signer)

	sshConnection, channels, requests, err := ssh.NewServerConn(connection, sshConfig)
	if err != nil {
		s.logger.Info("reject SSH connection", "remote", connection.RemoteAddr(), "error", err)
		return
	}
	defer sshConnection.Close()
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
		go s.serveSession(channel, requests, session)
	}
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

func (s *Server) serveSession(channel ssh.Channel, requests <-chan *ssh.Request, session auth.Session) {
	defer channel.Close()
	for request := range requests {
		if request.Type != "subsystem" {
			_ = request.Reply(false, nil)
			continue
		}

		var payload struct{ Name string }
		if err := ssh.Unmarshal(request.Payload, &payload); err != nil || payload.Name != "sftp" {
			_ = request.Reply(false, nil)
			continue
		}
		if err := request.Reply(true, nil); err != nil {
			return
		}

		filesystem := httpfs.New(session.User.RootFS, s.config.UploadStagingDir, session.Client)
		requestServer := sftp.NewRequestServer(channel, filesystem.Handlers())
		if err := requestServer.Serve(); err != nil && !errors.Is(err, io.EOF) {
			s.logger.Debug("serve SFTP request", "error", err)
		}
		return
	}
}
