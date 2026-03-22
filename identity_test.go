package raftsecure_test

import (
	"path/filepath"
	"testing"

	raftsecure "github.com/oltdaniel/raft-secure-transport"
)

func TestIdentity_NewIdenity(t *testing.T) {
	id, err := raftsecure.NewIdentity()
	if err != nil {
		t.Fatalf("failed to create identity: %v", err)
	}

	if id.Certificate == nil {
		t.Fatal("expected certificate to be set")
	}

	if id.PublicKey == nil {
		t.Fatal("expected public key to be set")
	}
}

func TestIdentity_CreateAndSave(t *testing.T) {
	id, err := raftsecure.NewIdentity()
	if err != nil {
		t.Fatalf("failed to create identity: %v", err)
	}

	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "node.crt")
	keyPath := filepath.Join(tempDir, "node.key")

	if err := id.Save(certPath, keyPath); err != nil {
		t.Fatalf("failed to save identity: %v", err)
	}

	loadedID, err := raftsecure.LoadIdentity(certPath, keyPath)
	if err != nil {
		t.Fatalf("failed to load identity: %v", err)
	}

	if loadedID.Certificate == nil {
		t.Fatal("expected certificate to be set")
	}

	if loadedID.PublicKey == nil {
		t.Fatal("expected public key to be set")
	}
}

func TestLoad(t *testing.T) {
	id, err := raftsecure.NewIdentity()
	if err != nil {
		t.Fatalf("failed to create identity: %v", err)
	}

	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "node.crt")
	keyPath := filepath.Join(tempDir, "node.key")

	if err := id.Save(certPath, keyPath); err != nil {
		t.Fatalf("failed to save identity: %v", err)
	}

	loadedID, err := raftsecure.LoadIdentity(certPath, keyPath)
	if err != nil {
		t.Fatalf("failed to load identity: %v", err)
	}

	if loadedID.Certificate == nil {
		t.Fatal("expected certificate to be set")
	}

	if loadedID.PublicKey == nil {
		t.Fatal("expected public key to be set")
	}
}
