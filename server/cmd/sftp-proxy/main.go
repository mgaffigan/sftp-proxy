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
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"

	"sftp-proxy/internal/config"
	"sftp-proxy/internal/server"
	"sftp-proxy/internal/telemetry"
)

const passwordHashCost = 12

func main() {
	configPath := flag.String("config", "sftp-proxy.json", "path to JSON configuration")
	hashPasswordFlag := flag.Bool("hash-password", false, "prompt for a password and print its bcrypt hash")
	flag.Parse()
	if *hashPasswordFlag {
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

	tracing, err := telemetry.New(context.Background())
	if err != nil {
		slog.Error("initialize telemetry", "error", err)
		os.Exit(1)
	}
	shutdownTelemetry := func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := tracing.Shutdown(shutdownCtx); err != nil {
			slog.Error("shutdown telemetry", "error", err)
		}
	}

	proxy, err := server.New(cfg, slog.Default())
	if err != nil {
		slog.Error("initialize server", "error", err)
		shutdownTelemetry()
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = proxy.ListenAndServe(ctx)
	shutdownTelemetry()
	if err != nil && !errors.Is(err, context.Canceled) {
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
