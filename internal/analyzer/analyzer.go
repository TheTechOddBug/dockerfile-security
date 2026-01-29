package analyzer

import (
	"fmt"
	"os"
	"time"

	"github.com/cr0hn/dockerfile-sec/internal/rules"
	"github.com/dlclark/regexp2"
)

// Analyze scans content against rules and returns matched issues.
// Rules with IDs in ignored are skipped. Invalid regexes are reported to stderr and skipped.
func Analyze(content string, ruleList []rules.Rule, ignored map[string]bool) []rules.Issue {
	var issues []rules.Issue

	for _, rule := range ruleList {
		if ignored[rule.ID] {
			continue
		}

		re, err := regexp2.Compile(rule.Regex, regexp2.Multiline)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: invalid regex for rule %s: %v\n", rule.ID, err)
			continue
		}

		re.MatchTimeout = 5 * time.Second

		match, err := re.MatchString(content)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: regex timeout/error for rule %s: %v\n", rule.ID, err)
			continue
		}

		if match {
			issues = append(issues, rules.IssueFromRule(rule))
		}
	}

	return issues
}
