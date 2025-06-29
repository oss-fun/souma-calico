package ipfw

import (
	"time"
)

type RuleSet struct {
	Name      string
	IPVersion uint8
	MainRule  []Rule
	ChainMap  map[string]Chain
}

type RulesetOptions struct {
	BackendMode       string
	RefreshInterval   time.Duration
	PostWriteInterval time.Duration

	LockTimeout time.Duration

	OnStillAlive func()
	OpRecorder logutils.OpRecorder
}

func NewRuleSet(name string, ipVersion uint8) *RuleSet {
	return &RuleSet {
		Name:      name,
		IPVersion: ipVersion,
	}
}

