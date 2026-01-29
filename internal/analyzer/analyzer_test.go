package analyzer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cr0hn/dockerfile-sec/internal/rules"
)

func loadTestDockerfile(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return string(data)
}

func TestAnalyzeDockerfileExample(t *testing.T) {
	content := loadTestDockerfile(t, "Dockerfile-example")
	allRules, err := rules.LoadInternal("all")
	if err != nil {
		t.Fatal(err)
	}

	issues := Analyze(content, allRules, nil)
	if len(issues) == 0 {
		t.Error("expected issues for Dockerfile-example, got none")
	}

	// Check specific expected matches
	foundIDs := make(map[string]bool)
	for _, issue := range issues {
		foundIDs[issue.ID] = true
	}

	// Dockerfile-example has: COPY . . (core-003), password in text (core-002),
	// FROM python:3.7-alpine (not sha256, core-005), no USER (core-001 should NOT match),
	// cred-001 (generic credential: password)
	expectedIDs := []string{"core-002", "core-003", "core-005"}
	for _, id := range expectedIDs {
		if !foundIDs[id] {
			t.Errorf("expected rule %s to match, but it didn't. Found: %v", id, foundIDs)
		}
	}
}

func TestAnalyzeWithIgnores(t *testing.T) {
	content := loadTestDockerfile(t, "Dockerfile-example")
	allRules, err := rules.LoadInternal("all")
	if err != nil {
		t.Fatal(err)
	}

	ignored := map[string]bool{"core-002": true, "core-003": true, "core-005": true}
	issues := Analyze(content, allRules, ignored)

	for _, issue := range issues {
		if ignored[issue.ID] {
			t.Errorf("rule %s should be ignored", issue.ID)
		}
	}
}

func TestAnalyzeCleanDockerfile(t *testing.T) {
	content := loadTestDockerfile(t, "Dockerfile-clean")
	allRules, err := rules.LoadInternal("all")
	if err != nil {
		t.Fatal(err)
	}

	issues := Analyze(content, allRules, nil)

	// Clean Dockerfile uses sha256 and USER, so it should have fewer issues
	foundIDs := make(map[string]bool)
	for _, issue := range issues {
		foundIDs[issue.ID] = true
	}

	// core-001 should match (USER is present, regex checks for absence via ^^)
	// core-003 should NOT match (no recursive COPY)
	if foundIDs["core-003"] {
		t.Error("core-003 should not match a clean Dockerfile")
	}
}

func TestAnalyzeInvalidRegex(t *testing.T) {
	content := "FROM ubuntu:latest"
	badRules := []rules.Rule{
		{ID: "bad-001", Description: "Bad regex", Regex: "[invalid", Severity: "Low"},
	}
	// Should not panic, just skip
	issues := Analyze(content, badRules, nil)
	if len(issues) != 0 {
		t.Errorf("expected 0 issues for invalid regex, got %d", len(issues))
	}
}

func TestAnalyzeEmpty(t *testing.T) {
	issues := Analyze("", nil, nil)
	if len(issues) != 0 {
		t.Errorf("expected 0 issues, got %d", len(issues))
	}
}

func TestAnalyzeCustomRule(t *testing.T) {
	content := "FROM ubuntu:latest\nEXPOSE 8080\n"
	customRules := []rules.Rule{
		{ID: "custom-001", Description: "Detects EXPOSE", Regex: `(EXPOSE[\s]+[\d]+)`, Severity: "Low", Reference: "https://example.com"},
	}
	issues := Analyze(content, customRules, nil)
	if len(issues) != 1 {
		t.Errorf("expected 1 issue, got %d", len(issues))
	}
	if len(issues) > 0 && issues[0].ID != "custom-001" {
		t.Errorf("expected custom-001, got %s", issues[0].ID)
	}
}
