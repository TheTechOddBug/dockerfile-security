package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/cr0hn/dockerfile-sec/internal/rules"
	"golang.org/x/term"
)

// Render outputs the analysis results as ASCII table (terminal) or JSON (pipe).
func Render(issues []rules.Issue, quiet bool, outputFile string) error {
	// Write JSON to file if -o specified
	if outputFile != "" && len(issues) > 0 {
		data, err := json.Marshal(issues)
		if err != nil {
			return fmt.Errorf("marshaling JSON: %w", err)
		}
		if err := os.WriteFile(outputFile, data, 0644); err != nil {
			return fmt.Errorf("writing output file: %w", err)
		}
	}

	if quiet {
		return nil
	}

	if term.IsTerminal(int(os.Stdout.Fd())) {
		return renderTable(issues)
	}
	return renderJSON(issues)
}

func renderTable(issues []rules.Issue) error {
	return renderTableTo(os.Stdout, issues)
}

func renderTableTo(w io.Writer, issues []rules.Issue) error {
	headers := []string{"Rule Id", "Description", "Severity"}

	if len(issues) == 0 {
		rows := [][]string{{"No issues found"}}
		printASCIITableTo(w, headers, rows)
		return nil
	}

	rows := make([][]string, len(issues))
	for i, issue := range issues {
		rows[i] = []string{issue.ID, issue.Description, issue.Severity}
	}
	printASCIITableTo(w, headers, rows)
	return nil
}

func printASCIITable(headers []string, rows [][]string) {
	printASCIITableTo(os.Stdout, headers, rows)
}

func printASCIITableTo(w io.Writer, headers []string, rows [][]string) {
	// Calculate column widths
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) && len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	// Build separator
	sepParts := make([]string, len(widths))
	for i, w := range widths {
		sepParts[i] = strings.Repeat("-", w+2)
	}
	sep := "+" + strings.Join(sepParts, "+") + "+"

	// Print header
	fmt.Fprintln(w, sep)
	printRowTo(w, headers, widths)
	fmt.Fprintln(w, sep)

	// Print rows
	for _, row := range rows {
		printRowTo(w, row, widths)
	}
	fmt.Fprintln(w, sep)
}

func printRow(cells []string, widths []int) {
	printRowTo(os.Stdout, cells, widths)
}

func printRowTo(w io.Writer, cells []string, widths []int) {
	parts := make([]string, len(widths))
	for i := range widths {
		cell := ""
		if i < len(cells) {
			cell = cells[i]
		}
		parts[i] = fmt.Sprintf(" %-*s ", widths[i], cell)
	}
	fmt.Fprintln(w, "|"+strings.Join(parts, "|")+"|")
}

func renderJSON(issues []rules.Issue) error {
	return renderJSONTo(os.Stdout, issues)
}

func renderJSONTo(w io.Writer, issues []rules.Issue) error {
	if issues == nil {
		issues = []rules.Issue{}
	}
	data, err := json.Marshal(issues)
	if err != nil {
		return fmt.Errorf("marshaling JSON: %w", err)
	}
	_, err = w.Write(data)
	return err
}
