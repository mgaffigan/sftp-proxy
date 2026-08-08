package vfs

import (
	"io"
	"os"
)

// StagingFile is scratch space that exists only for as long as it is open.
//
// It is unlinked the moment it is created, so the descriptor held here is the
// only reference to it. The space is reclaimed when that descriptor closes,
// including when the process dies without closing it, and no other process can
// reach the contents by name in the meantime. A platform that refuses to
// unlink an open file keeps the path and removes it on Close instead, which is
// the only case where a crash can leave anything behind.
type StagingFile struct {
	*os.File
	unlinked string // path still on disk, empty once unlinked
}

func NewStagingFile(dir, pattern string) (*StagingFile, error) {
	file, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return nil, ErrFailure
	}
	staging := &StagingFile{File: file}
	if err := os.Remove(file.Name()); err != nil {
		staging.unlinked = file.Name()
	}
	return staging, nil
}

func (f *StagingFile) Close() error {
	err := f.File.Close()
	if f.unlinked != "" {
		if removeErr := os.Remove(f.unlinked); err == nil {
			err = removeErr
		}
	}
	if err != nil {
		return ErrFailure
	}
	return nil
}

// StagedWriter collects a file's contents on local disk and hands them over as
// one sequential stream when the writer is closed.
//
// SFTP writes at arbitrary offsets, in whatever order a client chooses. Most
// backends can only be given a whole file at once, so they compose this rather
// than each solving the same problem. A backend able to write in place should
// not use it.
type StagedWriter struct {
	file   *StagingFile
	commit func(io.Reader) error
	err    error
}

// NewStagedWriter stages into dir, calling commit with the complete contents
// when Close is reached.
func NewStagedWriter(dir string, commit func(io.Reader) error) (*StagedWriter, error) {
	file, err := NewStagingFile(dir, "upload-*")
	if err != nil {
		return nil, err
	}
	return &StagedWriter{file: file, commit: commit}, nil
}

func (w *StagedWriter) WriteAt(data []byte, offset int64) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	count, err := w.file.WriteAt(data, offset)
	if err != nil {
		w.err = ErrFailure
		return count, w.err
	}
	return count, nil
}

// Close hands the staged contents to the backend. The contents are read back
// through the same descriptor they were written through, since after unlinking
// there is no name left to reopen.
func (w *StagedWriter) Close() error {
	defer w.file.Close()
	if w.err != nil {
		return w.err
	}
	if _, err := w.file.Seek(0, io.SeekStart); err != nil {
		return ErrFailure
	}
	return w.commit(w.file)
}
