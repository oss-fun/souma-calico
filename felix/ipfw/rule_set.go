//go:build freebsd

package ipfw

import (
	"regexp"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/iptables/cmdshim"
	"github.com/projectcalico/calico/felix/logutils"
	logutilslc "github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

type RuleSet struct {
	Name      string
	IPVersion uint8

	featureDetector environment.FeatureDetectorIface

	chainToAppendedRules map[string][]Rule
	chainNameToChain     map[string]*Chain
	dirtyAppend          set.Set[string]

	chainRefCounts map[string]int
	dirtyChains    set.Set[string]

	inSyncWithDataPlane bool

	chainToDataplaneHashes map[string][]string

	chainToFullRules map[string][]string

	hashCommentPrefix string
	hashCommentRegexp *regexp.Regexp
	ourChainsRegexp *regexp.Regexp
	oldInsertRegexp *regexp.Regexp

	iptablesRestoreCmd string
	iptablesSaveCmd    string

	insertMode string

	lastReadTime             time.Time
	lastWriteTime            time.Time
	initialPostWriteInterval time.Duration
	postWriteInterval        time.Duration
	refreshInterval          time.Duration

	peakIptablesSaveTime    time.Duration
	peakIptablesRestoreTime time.Duration

	calicoIpfwLock sync.Locker

	logCxt               *log.Entry
	updateRateLimitedLog *logutilslc.RateLimitedLogger

	gaugeNumChains        prometheus.Gauge
	gaugeNumRules         prometheus.Gauge
	countNumLinesExecuted prometheus.Counter

	restoreInputBuffer RestoreInputBuilder

	newCmd    cmdshim.CmdFactory
	timeSleep func(d time.Duration)
	timeNow   func() time.Time
	lookPath  func(file string) (string, error)

	onStillAlive func()
	opReporter   logutils.OpRecorder
	reason       string
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

