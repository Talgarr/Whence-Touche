// Package rules contains one Rule implementation per supported tool.
package rules

import "github.com/Talgarr/Whence-Touche/internal/classifier"

// All returns every registered rule.
// Classify picks the one with the highest Depth, so ordering here only
// matters when two rules match at exactly the same depth (tie-breaking).
func All() []classifier.Rule {
	return []classifier.Rule{
		SOPS{},
		Gopass{},
		Pass{},
		Age{},
		Git{},
		GPG{},
		Browser{},
		Auth{},
		SSH{},
	}
}
