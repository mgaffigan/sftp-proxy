package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"sftp-proxy/internal/config"
)

// Probes are paced in milliseconds, so these tests run in milliseconds too.
// settleTimeout is the ceiling for something that should happen almost at once;
// it is generous because exceeding it fails the test, whereas the assertions
// that must not fire early are driven by observed probe counts, not by waiting.
const (
	testClientAliveMs = 25
	settleTimeout     = 2 * time.Second
)

func TestClientAliveDisconnectsUnresponsiveClient(t *testing.T) {
	connection, _ := connectOverLoopback(t, false)
	countMax := 1
	closed := waitClosed(connection)
	go testServer().clientAlive(connection, config.User{
		ClientAliveMs:       testClientAliveMs,
		ClientAliveCountMax: &countMax,
	}, t.Context().Done())

	// One probe goes out after the interval and is never answered, so the
	// connection should close about one interval after that.
	select {
	case <-closed:
	case <-time.After(settleTimeout):
		t.Fatal("unresponsive client was not disconnected")
	}
}

func TestClientAliveKeepsResponsiveClient(t *testing.T) {
	connection, probes := connectOverLoopback(t, true)
	countMax := 2
	closed := waitClosed(connection)
	go testServer().clientAlive(connection, config.User{
		ClientAliveMs:       testClientAliveMs,
		ClientAliveCountMax: &countMax,
	}, t.Context().Done())

	// Wait for more probes than countMax to be answered rather than for a fixed
	// stretch of time: that is the condition that would have tripped the
	// disconnect had the answers not counted. x/crypto's client replies to
	// keepalive@openssh.com with a failure, which still proves liveness — the
	// same thing OpenSSH accepts.
	waitFor(t, "probes answered", func() bool { return probes() > countMax })
	select {
	case <-closed:
		t.Fatal("responsive client was disconnected")
	default:
	}
}

func TestClientAliveDisabled(t *testing.T) {
	connection, probes := connectOverLoopback(t, false)
	closed := waitClosed(connection)

	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		// No interval configured, so no probing regardless of countMax.
		testServer().clientAlive(connection, config.User{}, t.Context().Done())
	}()

	select {
	case <-stopped:
	case <-time.After(settleTimeout):
		t.Fatal("clientAlive did not return with probing disabled")
	}
	if probes() != 0 {
		t.Fatalf("probes sent = %d, want 0", probes())
	}
	select {
	case <-closed:
		t.Fatal("connection closed with probing disabled")
	default:
	}
}

func testServer() *Server {
	return &Server{logger: slog.New(slog.DiscardHandler)}
}

func waitFor(t *testing.T, what string, satisfied func() bool) {
	t.Helper()
	deadline := time.Now().Add(settleTimeout)
	for !satisfied() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func waitClosed(connection *ssh.ServerConn) <-chan struct{} {
	closed := make(chan struct{})
	go func() {
		_ = connection.Wait()
		close(closed)
	}()
	return closed
}

// connectOverLoopback completes an SSH handshake over a loopback socket and
// returns the server side plus a count of the global requests the client saw.
// When answerRequests is false the client reads probes but never replies, which
// is what a wedged client looks like to the server.
//
// A real socket rather than net.Pipe: the handshake opens with both sides
// writing a version banner before either reads, which an unbuffered pipe
// deadlocks on.
func connectOverLoopback(t *testing.T, answerRequests bool) (*ssh.ServerConn, func() int) {
	t.Helper()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverConfig := &ssh.ServerConfig{NoClientAuth: true}
	serverConfig.AddHostKey(signer)

	type handshake struct {
		connection *ssh.ServerConn
		err        error
	}
	accepted := make(chan handshake, 1)
	go func() {
		socket, err := listener.Accept()
		if err != nil {
			accepted <- handshake{err: err}
			return
		}
		connection, channels, requests, err := ssh.NewServerConn(socket, serverConfig)
		if err == nil {
			go ssh.DiscardRequests(requests)
			go func() {
				for channel := range channels {
					_ = channel.Reject(ssh.Prohibited, "")
				}
			}()
		}
		accepted <- handshake{connection, err}
	}()

	socket, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	clientConnection, channels, requests, err := ssh.NewClientConn(socket, listener.Addr().String(), &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientConnection.Close() })
	go func() {
		for range channels {
		}
	}()

	var seen atomic.Int64
	go func() {
		for request := range requests {
			seen.Add(1)
			if answerRequests && request.WantReply {
				_ = request.Reply(false, nil)
			}
		}
	}()

	result := <-accepted
	if result.err != nil {
		t.Fatalf("server handshake: %v", result.err)
	}
	t.Cleanup(func() { _ = result.connection.Close() })
	return result.connection, func() int { return int(seen.Load()) }
}
