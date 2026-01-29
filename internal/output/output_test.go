package output

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/cr0hn/dockerfile-sec/internal/rules"
)

func TestRenderJSONFile(t *testing.T) {
	issues := []rules.Issue{
		{ID: "core-001", Description: "Test issue", Reference: "https://example.com", Severity: "High"},
	}

	tmp, err := os.CreateTemp("", "output-*.json")
	if err != nil {
		t.Fatal(err)
	}
	tmp.Close()
	defer os.Remove(tmp.Name())

	// Render with quiet=true so no stdout, but write to file
	if err := Render(issues, true, tmp.Name()); err != nil {
		t.Fatalf("Render: %v", err)
	}

	data, err := os.ReadFile(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}

	var parsed []rules.Issue
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(parsed) != 1 {
		t.Errorf("expected 1 issue, got %d", len(parsed))
	}
	if parsed[0].ID != "core-001" {
		t.Errorf("expected core-001, got %s", parsed[0].ID)
	}
}

func TestRenderNoIssuesNoFile(t *testing.T) {
	// Should not error with empty issues
	if err := Render(nil, true, ""); err != nil {
		t.Fatalf("Render: %v", err)
	}
}

func TestRenderQuietSuppressesOutput(t *testing.T) {
	issues := []rules.Issue{
		{ID: "core-001", Description: "Test", Severity: "High"},
	}
	// quiet=true, no output file - should not error
	if err := Render(issues, true, ""); err != nil {
		t.Fatalf("Render: %v", err)
	}
}

func TestRenderTableFormat(t *testing.T) {
	tests := []struct {
		name     string
		issues   []rules.Issue
		contains []string
	}{
		{
			name:   "single issue",
			issues: []rules.Issue{{ID: "core-001", Description: "Test issue", Severity: "High"}},
			contains: []string{
				"Rule Id",
				"Description",
				"Severity",
				"core-001",
				"Test issue",
				"High",
				"+", "|", "-",
			},
		},
		{
			name:   "multiple issues",
			issues: []rules.Issue{{ID: "core-001", Description: "First", Severity: "High"}, {ID: "core-002", Description: "Second", Severity: "Medium"}},
			contains: []string{
				"core-001", "First", "High",
				"core-002", "Second", "Medium",
			},
		},
		{
			name:     "no issues",
			issues:   nil,
			contains: []string{"No issues found"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := renderTableTo(&buf, tt.issues); err != nil {
				t.Fatalf("renderTableTo: %v", err)
			}
			output := buf.String()
			for _, want := range tt.contains {
				if !strings.Contains(output, want) {
					t.Errorf("output missing %q\nGot:\n%s", want, output)
				}
			}
		})
	}
}

func TestRenderJSONFormat(t *testing.T) {
	tests := []struct {
		name   string
		issues []rules.Issue
	}{
		{
			name:   "single issue",
			issues: []rules.Issue{{ID: "core-001", Description: "Test", Reference: "https://example.com", Severity: "High"}},
		},
		{
			name:   "multiple issues",
			issues: []rules.Issue{{ID: "core-001", Description: "First", Severity: "High"}, {ID: "core-002", Description: "Second", Severity: "Medium"}},
		},
		{
			name:   "empty issues",
			issues: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := renderJSONTo(&buf, tt.issues); err != nil {
				t.Fatalf("renderJSONTo: %v", err)
			}

			var parsed []rules.Issue
			if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
				t.Fatalf("invalid JSON: %v\nGot: %s", err, buf.String())
			}

			expected := tt.issues
			if expected == nil {
				expected = []rules.Issue{}
			}
			if len(parsed) != len(expected) {
				t.Errorf("expected %d issues, got %d", len(expected), len(parsed))
			}
		})
	}
}

func TestPrintASCIITableColumnWidths(t *testing.T) {
	headers := []string{"ID", "Description"}
	rows := [][]string{
		{"short", "A very long description that should expand the column"},
		{"another", "Short"},
	}

	var buf bytes.Buffer
	printASCIITableTo(&buf, headers, rows)
	output := buf.String()

	// Verify the table is properly formatted
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) < 5 {
		t.Fatalf("expected at least 5 lines, got %d", len(lines))
	}

	// All separator lines should have the same length
	sepLen := len(lines[0])
	for i, line := range lines {
		if strings.HasPrefix(line, "+") {
			if len(line) != sepLen {
				t.Errorf("line %d has different length: %d vs %d", i, len(line), sepLen)
			}
		}
	}
}

func TestPrintRowPadding(t *testing.T) {
	var buf bytes.Buffer
	widths := []int{10, 20}
	cells := []string{"short", "medium text"}

	printRowTo(&buf, cells, widths)
	output := buf.String()

	// Should have proper padding
	if !strings.HasPrefix(output, "|") || !strings.HasSuffix(strings.TrimSpace(output), "|") {
		t.Errorf("row should be bounded by pipes: %s", output)
	}
}

func TestRenderEmptyIssuesCreatesEmptyArrayJSON(t *testing.T) {
	tmp, err := os.CreateTemp("", "empty-*.json")
	if err != nil {
		t.Fatal(err)
	}
	tmp.Close()
	defer os.Remove(tmp.Name())

	// Empty issues should not write to file
	if err := Render(nil, true, tmp.Name()); err != nil {
		t.Fatalf("Render: %v", err)
	}

	// File should not exist or be empty since len(issues) == 0
	data, err := os.ReadFile(tmp.Name())
	if err == nil && len(data) > 0 {
		t.Errorf("expected no file content for empty issues, got: %s", data)
	}
}

func TestRenderWritesToFile(t *testing.T) {
	issues := []rules.Issue{
		{ID: "test-001", Description: "Test", Reference: "https://example.com", Severity: "Low"},
	}

	tmp, err := os.CreateTemp("", "output-*.json")
	if err != nil {
		t.Fatal(err)
	}
	tmp.Close()
	defer os.Remove(tmp.Name())

	if err := Render(issues, false, tmp.Name()); err != nil {
		t.Fatalf("Render: %v", err)
	}

	data, err := os.ReadFile(tmp.Name())
	if err != nil {
		t.Fatalf("reading output file: %v", err)
	}

	var parsed []rules.Issue
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid JSON in file: %v", err)
	}

	if len(parsed) != 1 || parsed[0].ID != "test-001" {
		t.Errorf("unexpected file content: %+v", parsed)
	}
}
