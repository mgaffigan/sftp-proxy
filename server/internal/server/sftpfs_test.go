package server

import (
	"errors"
	"io"
	"os"
	"testing"

	"github.com/pkg/sftp"

	"sftp-proxy/internal/config"
	"sftp-proxy/internal/vfs"
)

func TestFilesystemOutcomesBecomeSFTPStatuses(t *testing.T) {
	cases := []struct {
		from error
		want error
	}{
		{vfs.ErrNotExist, sftp.ErrSSHFxNoSuchFile},
		{vfs.ErrPermission, sftp.ErrSSHFxPermissionDenied},
		{vfs.ErrUnsupported, sftp.ErrSSHFxOpUnsupported},
		{vfs.ErrFailure, sftp.ErrSSHFxFailure},
		{vfs.ErrExist, sftp.ErrSSHFxFailure},
		// Anything unrecognised must not travel as itself: pkg/sftp puts a bare
		// error's text on the wire, where it would describe the backend to a
		// client that must not learn about it.
		{errors.New("dial tcp 10.0.0.7:443: connect: refused"), sftp.ErrSSHFxFailure},
	}
	for _, testCase := range cases {
		got := statusError(testCase.from)
		if !errors.Is(got, testCase.want) {
			t.Errorf("statusError(%v) = %v, want %v", testCase.from, got, testCase.want)
		}
	}
	if statusError(nil) != nil {
		t.Errorf("statusError(nil) = %v, want nil", statusError(nil))
	}
}

func TestNodesBecomeFileInfo(t *testing.T) {
	file := fileInfoFor(vfs.Node{File: "report.txt", Size: 42})
	if file.Name() != "report.txt" || file.Size() != 42 || file.IsDir() {
		t.Errorf("file info = %+v", file)
	}
	if file.Mode().IsDir() || file.Mode().Perm() != 0666 {
		t.Errorf("file mode = %v", file.Mode())
	}

	directory := fileInfoFor(vfs.Node{Directory: "outbound"})
	if directory.Name() != "outbound" || !directory.IsDir() {
		t.Errorf("directory info = %+v", directory)
	}
	if !directory.Mode().IsDir() || directory.Mode().Perm() != 0777 {
		t.Errorf("directory mode = %v", directory.Mode())
	}
}

func TestListerWalksAndEndsAtEOF(t *testing.T) {
	entries := lister{entries: []os.FileInfo{
		fileInfoFor(vfs.Node{File: "a"}),
		fileInfoFor(vfs.Node{File: "b"}),
		fileInfoFor(vfs.Node{File: "c"}),
	}}

	target := make([]os.FileInfo, 2)
	count, err := entries.ListAt(target, 0)
	if count != 2 || err != nil {
		t.Fatalf("ListAt(0) = (%d, %v), want (2, nil)", count, err)
	}
	if target[0].Name() != "a" || target[1].Name() != "b" {
		t.Fatalf("first page = %v, %v", target[0].Name(), target[1].Name())
	}

	// A short final page reports EOF along with what it filled.
	count, err = entries.ListAt(target, 2)
	if count != 1 || !errors.Is(err, io.EOF) {
		t.Fatalf("ListAt(2) = (%d, %v), want (1, EOF)", count, err)
	}
	count, err = entries.ListAt(target, 3)
	if count != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("ListAt(3) = (%d, %v), want (0, EOF)", count, err)
	}
}

func TestUnsupportedRequestMethodsAreRefused(t *testing.T) {
	adapter := &sftpFS{fs: vfs.New(config.RootFS{}, nil)}

	if err := adapter.Filecmd(sftp.NewRequest("Symlink", "/a")); !errors.Is(err, sftp.ErrSSHFxOpUnsupported) {
		t.Errorf("Filecmd(Symlink) = %v, want op unsupported", err)
	}
	if _, err := adapter.Filelist(sftp.NewRequest("Readlink", "/a")); !errors.Is(err, sftp.ErrSSHFxOpUnsupported) {
		t.Errorf("Filelist(Readlink) = %v, want op unsupported", err)
	}
}
