package ignore

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// Load builds a set of rule IDs to ignore from CLI -i flags and -F ignore files.
func Load(cliRules []string, ignoreFiles []string) (map[string]bool, error) {
	ignored := make(map[string]bool)

	// Parse comma-separated IDs from -i flags
	for _, r := range cliRules {
		for _, id := range strings.Split(r, ",") {
			id = strings.TrimSpace(id)
			if id != "" {
				ignored[id] = true
			}
		}
	}

	// Load IDs from ignore files (-F flags)
	for _, f := range ignoreFiles {
		ids, err := loadIgnoreSource(f)
		if err != nil {
			return nil, err
		}
		for _, id := range ids {
			if id != "" {
				ignored[id] = true
			}
		}
	}

	return ignored, nil
}

func loadIgnoreSource(source string) ([]string, error) {
	var content string

	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		resp, err := http.Get(source)
		if err != nil {
			return nil, fmt.Errorf("fetching ignore file %s: %w", source, err)
		}
		defer resp.Body.Close()

		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("reading ignore file %s: %w", source, err)
		}
		content = string(data)
	} else {
		data, err := os.ReadFile(source)
		if err != nil {
			return nil, fmt.Errorf("reading ignore file %s: %w", source, err)
		}
		content = string(data)
	}

	var ids []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			ids = append(ids, line)
		}
	}
	return ids, nil
}
