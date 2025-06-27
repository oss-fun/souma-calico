package ipfw

import (
)

type RuleSet struct {
	Name      string
	IPVersion uint8
	MainRule  []Rule
	ChainMap  map[string]Chain
}

func NewRuleSet(name string, ipVersion uint8) *RuleSet {
	return &RuleSet {
		Name:      name,
		IPVersion: ipVersion,
	}
}

