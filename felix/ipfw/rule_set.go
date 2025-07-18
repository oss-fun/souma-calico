//go:build freebsd

package ipfw

import (
	"fmt"
	"regexp"
	"sync"
	"strings"
	"os/exec"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/iptables/cmdshim"
	"github.com/projectcalico/calico/felix/logutils"
	logutilslc "github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

const (
	MaxChainNameLength = 28
	minPostWriteInterval = 50 * time.Millisecond
)

var (
	chainCreateRegexp = regexp.MustCompile(`^:(\S+)`)
	appendRegexp = regexp.MustCompile(`^-A (\S+)`)

	countNumRestoreCalls = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_ipfw_restore_calls",
		Help: "Number of ipfw-restore calls.",
	})
	countNumRestoreErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_ipfw_restore_errors",
		Help: "Number of ipfw-restore errors.",
	})
	countNumSaveCalls = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_iptfw_save_calls",
		Help: "Number of ipfw-save calls.",
	})
	countNumSaveErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_ipfw_save_errors",
		Help: "Number of ipfw-save errors.",
	})
	gaugeNumChains = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "felix_ipfw_chains",
		Help: "Number of active ipfw chains.",
	}, []string{"ip_version", "ruleset"})
	gaugeNumRules = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "felix_ipfw_rules",
		Help: "Number of active ipfw rules.",
	}, []string{"ip_version", "ruleset"})
	countNumLinesExecuted = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "felix_ipfw_lines_executed",
		Help: "Number of ipfw rule updates executed.",
	}, []string{"ip_version", "ruleset"})
)

func init() {
	prometheus.MustRegister(countNumRestoreCalls)
	prometheus.MustRegister(countNumRestoreErrors)
	prometheus.MustRegister(countNumSaveCalls)
	prometheus.MustRegister(countNumSaveErrors)
	prometheus.MustRegister(gaugeNumChains)
	prometheus.MustRegister(gaugeNumRules)
	prometheus.MustRegister(countNumLinesExecuted)
}

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

	ipfwCmd string

	insertMode string

	lastReadTime             time.Time
	lastWriteTime            time.Time
	initialPostWriteInterval time.Duration
	postWriteInterval        time.Duration
	refreshInterval          time.Duration

	peakIptablesSaveTime    time.Duration
	peakIptablesRestoreTime time.Duration

	calicoIpfwLock sync.Locker

	lockTimeout time.Duration
	lockProbeInterval time.Duration

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
	HistoricChainPrefixes    []string
	ExtraCleanupRegexPattern string
	BackendMode              string
	InsertMode               string
	RefreshInterval          time.Duration
	PostWriteInterval        time.Duration

	LockTimeout time.Duration
	LockProbeInterval time.Duration

	NewCmdOverride cmdshim.CmdFactory
	SleepOverride func(d time.Duration)
	NowOverride func() time.Time
	LookPathOverride func(file string) (string, error)
	OnStillAlive func()
	OpRecorder logutils.OpRecorder
}

func NewRuleSet(
	name string,
	ipVersion uint8,
	hashPrefix string,
	ipfwWriteLock sync.Locker,
	featureDetector environment.FeatureDetectorIface,
	options RulesetOptions,
) *RuleSet {
	hashCommentRegexp := regexp.MustCompile(`--comment "?` + hashPrefix + `([a-zA-Z0-9_-]+)"?`)
	ourChainsPattern := "^(" + strings.Join(options.HistoricChainPrefixes, "|") + ")"
	ourChainsRegexp := regexp.MustCompile(ourChainsPattern)

	oldInsertRegexpParts := []string{}
	for _, prefix := range options.HistoricChainPrefixes {
		part := fmt.Sprintf("(?:-j|--jump) %s", prefix)
		oldInsertRegexpParts = append(oldInsertRegexpParts, part)
	}
	if options.ExtraCleanupRegexPattern != "" {
		oldInsertRegexpParts = append(oldInsertRegexpParts,
			options.ExtraCleanupRegexPattern)
	}
	oldInsertPattern := strings.Join(oldInsertRegexpParts, "|")
	log.WithField("pattern", oldInsertPattern).Info("Calculated old-insert detection regex.")
	oldInsertRegexp := regexp.MustCompile(oldInsertPattern)

	appends := map[string][]Rule{}
	dirtyAppend := set.New[string]()
	refcounts := map[string]int{}
	appends["all"] = []Rule{}
	dirtyAppend.Add("all")
	refcounts["all"] += 1

	var insertMode string
	switch options.InsertMode {
	case "append":
		insertMode = "append"
	default:
		log.WithField("insertMode", options.InsertMode).Panic("Unknown insert mode")
	}

	if options.PostWriteInterval <= minPostWriteInterval {
		log.WithFields(log.Fields{
			"setValue": options.PostWriteInterval,
			"default":  minPostWriteInterval,
		}).Info("PostWriteInterval too small, defaulting.")
		options.PostWriteInterval = minPostWriteInterval
	}

	newCmd := cmdshim.NewRealCmd
	if options.NewCmdOverride != nil {
		newCmd = options.NewCmdOverride
	}
	sleep := time.Sleep
	if options.SleepOverride != nil {
		sleep = options.SleepOverride
	}
	now := time.Now
	if options.NowOverride != nil {
		now = options.NowOverride
	}
	lookPath := exec.LookPath
	if options.LookPathOverride != nil {
		lookPath = options.LookPathOverride
	}

	logFields := log.Fields{
		"ipVersion": ipVersion,
		"table":     name,
	}
	ruleset := &RuleSet{
		Name:                   name,
		IPVersion:              ipVersion,
		featureDetector:        featureDetector,
		chainToAppendedRules:   appends,
		dirtyAppend:      dirtyAppend,
		chainNameToChain:       map[string]*Chain{},
		chainRefCounts:         refcounts,
		dirtyChains:            set.New[string](),
		chainToDataplaneHashes: map[string][]string{},
		chainToFullRules:       map[string][]string{},
		logCxt:                 log.WithFields(logFields),
		updateRateLimitedLog: logutilslc.NewRateLimitedLogger(
			logutilslc.OptInterval(30*time.Second),
			logutilslc.OptBurst(100),
		).WithFields(logFields),
		hashCommentPrefix: hashPrefix,
		hashCommentRegexp: hashCommentRegexp,
		ourChainsRegexp:   ourChainsRegexp,
		oldInsertRegexp:   oldInsertRegexp,
		insertMode:        insertMode,

		lastWriteTime:            now(),
		initialPostWriteInterval: options.PostWriteInterval,
		postWriteInterval:        options.PostWriteInterval,

		refreshInterval: options.RefreshInterval,

		calicoIpfwLock: ipfwWriteLock,

		lockTimeout:       options.LockTimeout,
		lockProbeInterval: options.LockProbeInterval,

		newCmd:    newCmd,
		timeSleep: sleep,
		timeNow:   now,
		lookPath:  lookPath,

		gaugeNumChains:        gaugeNumChains.WithLabelValues(fmt.Sprintf("%d", ipVersion), name),
		gaugeNumRules:         gaugeNumRules.WithLabelValues(fmt.Sprintf("%d", ipVersion), name),
		countNumLinesExecuted: countNumLinesExecuted.WithLabelValues(fmt.Sprintf("%d", ipVersion), name),
		opReporter:            options.OpRecorder,
	}
	ruleset.restoreInputBuffer.NumLinesWritten = ruleset.countNumLinesExecuted

	if options.OnStillAlive != nil {
		ruleset.onStillAlive = options.OnStillAlive
	} else {
		ruleset.onStillAlive = func() {}
	}

	ipfwVariant := strings.ToLower(options.BackendMode)

	ruleset.ipfwCmd = environment.FindBestBinary(ruleset.lookPath, ipVersion, ipfwVariant, "")

	return ruleset
}

func (t *RuleSet) chainIsReferenced(name string) bool {
	return t.chainRefCounts[name] > 0
}

func (t *RuleSet) maybeDecrefReferredChains(chainName string, rules []Rule) {
	if !t.chainIsReferenced(chainName) {
		return
	}
}

func (t *RuleSet) InvalidateDataplaneCache(reason string) {
	logCxt := t.logCxt.WithField("reason", reason)
	if !t.inSyncWithDataPlane {
		logCxt.Debug("Would invalidate dataplane cache but it was already invalid.")
		return
	}
	logCxt.Debug("Invalidating dataplane cache")
	t.inSyncWithDataPlane = false
	t.reason = reason
}


func (t *RuleSet) RemoveChainByName(name string) {
	t.logCxt.WithField("chainName", name).Debug("Removing chain from available set.")
	if oldChain, known := t.chainNameToChain[name]; known {
		t.gaugeNumRules.Sub(float64(len(oldChain.Rules)))
		t.maybeDecrefReferredChains(name, oldChain.Rules)
		delete(t.chainNameToChain, name)
		if t.chainIsReferenced(name) {
			t.dirtyChains.Add(name)

			t.InvalidateDataplaneCache("chain removal")
		}
	}
}

func (t *RuleSet) decrefChain(chainName string) {
	log.WithField("chainName", chainName).Debug("Decref chain")
	if t.chainRefCounts[chainName] == 1 {
		t.updateRateLimitedLog.WithField("chainName", chainName).Info("Chain no longer referenced, marking it for removal")
		if chain := t.chainNameToChain[chainName]; chain != nil {
			t.maybeDecrefReferredChains(chainName, chain.Rules)
		}
		delete(t.chainRefCounts, chainName)
		t.dirtyChains.Add(chainName)
		return
	}

	t.chainRefCounts[chainName] -= 1
}

func (r RuleSet) GetChainNum(name string) uint16 {
	return r.chainNameToChain[name].GetStartRuleNum()
}
