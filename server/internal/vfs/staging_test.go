package vfs

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

// entries reports what is left in a staging directory.
func entries(t *testing.T, dir string) []string {
	t.Helper()
	found, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(found))
	for _, entry := range found {
		names = append(names, entry.Name())
	}
	return names
}

func TestStagingFileIsGoneBeforeItIsEverWritten(t *testing.T) {
	dir := t.TempDir()
	file, err := NewStagingFile(dir, "scratch-*")
	if err != nil {
		t.Fatalf("NewStagingFile() error = %v", err)
	}
	defer file.Close()

	// Unlinked at creation: nothing on disk to leak if the process dies here,
	// and no name another process could open in the meantime.
	if left := entries(t, dir); len(left) != 0 {
		t.Fatalf("staging directory holds %v, want the file already unlinked", left)
	}

	// The descriptor still works, which is the whole point.
	if _, err := file.WriteAt([]byte("still usable"), 0); err != nil {
		t.Fatalf("WriteAt() error = %v", err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("Seek() error = %v", err)
	}
	contents, err := io.ReadAll(file)
	if err != nil || string(contents) != "still usable" {
		t.Fatalf("read back %q, %v", contents, err)
	}
}

func TestStagedWriterCommitsWhatWasWrittenAndLeavesNothing(t *testing.T) {
	dir := t.TempDir()
	var committed string
	writer, err := NewStagedWriter(dir, func(contents *StagingFile) error {
		data, err := io.ReadAll(contents)
		committed = string(data)
		return err
	})
	if err != nil {
		t.Fatalf("NewStagedWriter() error = %v", err)
	}

	// Written out of order, as an SFTP client may.
	if _, err := writer.WriteAt([]byte("world"), 6); err != nil {
		t.Fatalf("WriteAt() error = %v", err)
	}
	if _, err := writer.WriteAt([]byte("hello "), 0); err != nil {
		t.Fatalf("WriteAt() error = %v", err)
	}
	if committed != "" {
		t.Fatal("contents were committed before Close")
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if committed != "hello world" {
		t.Fatalf("committed %q, want hello world", committed)
	}
	if left := entries(t, dir); len(left) != 0 {
		t.Fatalf("staging directory holds %v after close", left)
	}
}

func TestStagedWriterLeavesNothingWhenTheCommitFails(t *testing.T) {
	dir := t.TempDir()
	refused := errors.New("backend refused")
	writer, err := NewStagedWriter(dir, func(*StagingFile) error { return refused })
	if err != nil {
		t.Fatalf("NewStagedWriter() error = %v", err)
	}
	if _, err := writer.WriteAt([]byte("doomed"), 0); err != nil {
		t.Fatalf("WriteAt() error = %v", err)
	}
	if err := writer.Close(); !errors.Is(err, refused) {
		t.Fatalf("Close() error = %v, want the backend's refusal", err)
	}
	if left := entries(t, dir); len(left) != 0 {
		t.Fatalf("staging directory holds %v after a failed commit", left)
	}
}

func TestStagedWriterDoesNotCommitAfterWriteFails(t *testing.T) {
	dir := t.TempDir()
	committed := false
	writer, err := NewStagedWriter(dir, func(*StagingFile) error {
		committed = true
		return nil
	})
	if err != nil {
		t.Fatalf("NewStagedWriter() error = %v", err)
	}

	if _, err := writer.WriteAt([]byte("doomed"), -1); !errors.Is(err, ErrFailure) {
		t.Fatalf("WriteAt() error = %v, want ErrFailure", err)
	}
	if _, err := writer.WriteAt([]byte("also doomed"), 0); !errors.Is(err, ErrFailure) {
		t.Fatalf("WriteAt() error = %v, want ErrFailure", err)
	}
	if err := writer.Close(); !errors.Is(err, ErrFailure) {
		t.Fatalf("Close() error = %v, want ErrFailure", err)
	}
	if committed {
		t.Fatal("commit was called after a failed write")
	}
	if left := entries(t, dir); len(left) != 0 {
		t.Fatalf("staging directory holds %v after a failed write", left)
	}
}

func TestStagedWriterCommitsALargeSparseFileWhole(t *testing.T) {
	dir := t.TempDir()
	var size int
	writer, err := NewStagedWriter(dir, func(contents *StagingFile) error {
		data, err := io.ReadAll(contents)
		size = len(data)
		return err
	})
	if err != nil {
		t.Fatalf("NewStagedWriter() error = %v", err)
	}

	// A gap between writes is read back as the zero bytes the file holds, so
	// the committed length reaches the furthest offset written. Note that this
	// records what staging does today rather than what it should: a client that
	// writes one far offset and closes commits a zero-filled file, and neither
	// a gap nor an earlier failed write is detected here.
	if _, err := writer.WriteAt([]byte("end"), 1<<20); err != nil {
		t.Fatalf("WriteAt() error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if size != 1<<20+3 {
		t.Fatalf("committed %d bytes, want %d", size, 1<<20+3)
	}
}

func TestStagingErrorsSayNothingOfTheFilesystem(t *testing.T) {
	// A staging directory that does not exist must not put its path in an
	// error a client could see.
	_, err := NewStagingFile("/nonexistent/private/staging/path", "scratch-*")
	if !errors.Is(err, ErrFailure) {
		t.Fatalf("NewStagingFile() error = %v, want failure", err)
	}
	if strings.Contains(err.Error(), "nonexistent") {
		t.Fatalf("error names the staging path: %v", err)
	}
}
