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

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"sftp-proxy/internal/auth"
	"sftp-proxy/internal/config"
	"sftp-proxy/internal/httpfs"
)

type Server struct {
	config    config.Config
	sshConfig *ssh.ServerConfig
	auth      *auth.Authenticator
	logger    *slog.Logger
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

	server := &Server{config: cfg, auth: auth.New(cfg), logger: logger}
	server.sshConfig = &ssh.ServerConfig{
		PasswordCallback:  server.auth.Password,
		PublicKeyCallback: server.auth.PublicKey,
	}
	server.sshConfig.AddHostKey(signer)
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
	sshConnection, channels, requests, err := ssh.NewServerConn(connection, s.sshConfig)
	if err != nil {
		s.logger.Info("reject SSH connection", "remote", connection.RemoteAddr(), "error", err)
		return
	}
	defer sshConnection.Close()
	session, ok := auth.SessionFrom(sshConnection.Permissions)
	if !ok {
		s.logger.Error("authenticated session has no user configuration", "user", sshConnection.User())
		return
	}

	s.logger.Info("accept SSH connection", "user", sshConnection.User(), "remote", sshConnection.RemoteAddr())
	go ssh.DiscardRequests(requests)

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
