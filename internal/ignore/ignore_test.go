package ignore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCommaSeparated(t *testing.T) {
	ignored, err := Load([]string{"core-001,core-002", "cred-001"}, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	expected := map[string]bool{"core-001": true, "core-002": true, "cred-001": true}
	for id := range expected {
		if !ignored[id] {
			t.Errorf("expected %s to be ignored", id)
		}
	}
	if len(ignored) != 3 {
		t.Errorf("expected 3 ignored, got %d", len(ignored))
	}
}

func TestLoadFromIgnoreFile(t *testing.T) {
	ignoreFile := filepath.Join("..", "..", "testdata", "ignore-1")
	ignored, err := Load(nil, []string{ignoreFile})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !ignored["core-001"] {
		t.Error("expected core-001 to be ignored")
	}
	if !ignored["core-007"] {
		t.Error("expected core-007 to be ignored")
	}
}

func TestLoadWhitespace(t *testing.T) {
	tmp, err := os.CreateTemp("", "ignore-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.WriteString("  core-001  \n\ncore-002\n  \n"); err != nil {
		t.Fatal(err)
	}
	tmp.Close()

	ignored, err := Load(nil, []string{tmp.Name()})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !ignored["core-001"] {
		t.Error("expected core-001")
	}
	if !ignored["core-002"] {
		t.Error("expected core-002")
	}
	if len(ignored) != 2 {
		t.Errorf("expected 2, got %d", len(ignored))
	}
}

func TestLoadEmpty(t *testing.T) {
	ignored, err := Load(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(ignored) != 0 {
		t.Errorf("expected 0, got %d", len(ignored))
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(nil, []string{"/nonexistent/file"})
	if err == nil {
		t.Error("expected error for missing file")
	}
}
