package main

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestHashPassword(t *testing.T) {
	hash, err := hashPassword([]byte("correct horse battery staple"))
	if err != nil {
		t.Fatalf("hashPassword() error = %v", err)
	}
	if err := bcrypt.CompareHashAndPassword(hash, []byte("correct horse battery staple")); err != nil {
		t.Fatalf("CompareHashAndPassword() error = %v", err)
	}
	cost, err := bcrypt.Cost(hash)
	if err != nil {
		t.Fatalf("Cost() error = %v", err)
	}
	if cost != passwordHashCost {
		t.Fatalf("Cost() = %d, want %d", cost, passwordHashCost)
	}
}

func TestHashPasswordRejectsEmptyPassword(t *testing.T) {
	if _, err := hashPassword(nil); err == nil {
		t.Fatal("hashPassword() succeeded with an empty password")
	}
}
