package rules

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/cr0hn/dockerfile-sec/internal/rules/embedded"
	"gopkg.in/yaml.v3"
)

// Rule represents a single security rule loaded from YAML.
type Rule struct {
	ID          string `yaml:"id" json:"id"`
	Description string `yaml:"description" json:"description"`
	Regex       string `yaml:"regex" json:"-"`
	Reference   string `yaml:"reference" json:"reference"`
	Severity    string `yaml:"severity" json:"severity"`
}

// Issue represents a matched rule (without the regex field).
type Issue struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Reference   string `json:"reference"`
	Severity    string `json:"severity"`
}

// IssueFromRule creates an Issue from a Rule, omitting the regex.
func IssueFromRule(r Rule) Issue {
	return Issue{
		ID:          r.ID,
		Description: r.Description,
		Reference:   r.Reference,
		Severity:    r.Severity,
	}
}

// LoadInternal loads built-in rules based on the selection flag.
// Valid selections: "all" (default), "core", "credentials", "none".
func LoadInternal(selection string) ([]Rule, error) {
	switch strings.ToLower(selection) {
	case "none":
		return nil, nil
	case "core":
		return parseYAML(embedded.CoreYAML)
	case "credentials":
		return parseYAML(embedded.CredentialsYAML)
	case "all", "":
		core, err := parseYAML(embedded.CoreYAML)
		if err != nil {
			return nil, err
		}
		creds, err := parseYAML(embedded.CredentialsYAML)
		if err != nil {
			return nil, err
		}
		return append(core, creds...), nil
	default:
		return nil, fmt.Errorf("unknown rule selection: %s", selection)
	}
}

// LoadExternal loads rules from a file path or URL.
func LoadExternal(source string) ([]Rule, error) {
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		return LoadFromURL(source)
	}
	return LoadFromFile(source)
}

// LoadFromFile loads rules from a local YAML file.
func LoadFromFile(path string) ([]Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading rules file %s: %w", path, err)
	}
	return parseYAML(data)
}

// LoadFromURL loads rules from a remote YAML URL.
func LoadFromURL(url string) ([]Rule, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetching rules from %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching rules from %s: status %d", url, resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading rules from %s: %w", url, err)
	}
	return parseYAML(data)
}

func parseYAML(data []byte) ([]Rule, error) {
	var rules []Rule
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("parsing rules YAML: %w", err)
	}
	return rules, nil
}
