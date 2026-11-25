//go:build !windows

package remediation

import (
	"os"
	"path/filepath"
	"testing"
)

// We can't become another user in a unit test, so capture what we'd chown to.
func captureChown(t *testing.T) *[]string {
	t.Helper()
	var calls []string
	orig := chown
	chown = func(name string, uid, gid int) error {
		calls = append(calls, name)
		return nil
	}
	t.Cleanup(func() { chown = orig })
	return &calls
}

func TestAtomicWrite_PreservesOwner(t *testing.T) {
	calls := captureChown(t)
	path := filepath.Join(t.TempDir(), "docker-compose.yml")
	if err := os.WriteFile(path, []byte("a"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWrite(path, []byte("b"), 0644); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 1 {
		t.Fatalf("expected the temp file to be chowned to the original owner, got calls %v", *calls)
	}
}

func TestCreateBackup_PreservesOwner(t *testing.T) {
	calls := captureChown(t)
	path := filepath.Join(t.TempDir(), "docker-compose.yml")
	if err := os.WriteFile(path, []byte("a"), 0644); err != nil {
		t.Fatal(err)
	}
	backup, err := CreateBackup(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 1 || (*calls)[0] != backup {
		t.Fatalf("expected backup %s to be chowned, got calls %v", backup, *calls)
	}
}

func TestAtomicWrite_FollowsSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real", "compose.yml")
	if err := os.MkdirAll(filepath.Dir(real), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(real, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "docker-compose.yml")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	if err := AtomicWrite(link, []byte("new"), 0644); err != nil {
		t.Fatal(err)
	}

	fi, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("symlink was replaced by a regular file")
	}
	got, _ := os.ReadFile(real)
	if string(got) != "new" {
		t.Fatalf("real file has %q, want %q", got, "new")
	}
}
