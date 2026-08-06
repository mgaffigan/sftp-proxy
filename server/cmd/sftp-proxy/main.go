package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"

	"sftp-proxy/internal/config"
	"sftp-proxy/internal/server"
)

const passwordHashCost = 12

func main() {
	configPath := flag.String("config", "sftp-proxy.json", "path to JSON configuration")
	hashPassword := flag.Bool("hash-password", false, "prompt for a password and print its bcrypt hash")
	flag.Parse()
	if *hashPassword {
		if err := printPasswordHash(); err != nil {
			slog.Error("generate password hash", "error", err)
			os.Exit(1)
		}
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("load configuration", "error", err)
		os.Exit(1)
	}

	proxy, err := server.New(cfg, slog.Default())
	if err != nil {
		slog.Error("initialize server", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := proxy.ListenAndServe(ctx); err != nil && !errors.Is(err, context.Canceled) {
		slog.Error("serve", "error", err)
		os.Exit(1)
	}
}

func printPasswordHash() error {
	fmt.Fprint(os.Stderr, "Password: ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return err
	}
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(os.Stdout, string(hash))
	return err
}

func hashPassword(password []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, errors.New("password cannot be empty")
	}
	return bcrypt.GenerateFromPassword(password, passwordHashCost)
}
