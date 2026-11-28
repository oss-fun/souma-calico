//go:build freebsd

package ipfw

import (
	"bufio"
	"fmt"
	"regexp"
	"sync"
	"strings"
	"strconv"
	"reflect"
	"os"
	"os/exec"
	"time"
	"io"

	"github.com/google/go-cmp/cmp"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/ipfw/cmdshim"
	"github.com/projectcalico/calico/felix/logutils"
	logutilslc "github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

const (
	MaxChainNameLength = 28
	minPostWriteInterval = 50 * time.Millisecond
)

var (
	//chainCreateRegexp = regexp.MustCompile(`// chainName: (.*?) //`)
	appendRegexp = regexp.MustCompile(`// cali:([^:]+):(.+)`)

	// List of all the top-level kernel-created chains by iptables table.
	tableToKernelChains = map[string][]string{
		"filter": {"F-INPUT", "F-FORWARD", "F-OUTPUT"},
		"nat":    {"N-PREROUTING", "N-INPUT", "N-OUTPUT", "N-POSTROUTING"},
		"mangle": {"M-PREROUTING", "M-INPUT", "M-FORWARD", "M-OUTPUT", "M-POSTROUTING"},
		"raw":    {"R-PREROUTING", "R-OUTPUT"},
	}

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

var ChainNameToChain map[string]*Chain

func init() {
	ChainNameToChain = make(map[string]*Chain)

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

	chainToInsertedRules map[string][]Rule
	chainToAppendedRules map[string][]Rule
	chainNameToChain     map[string]*Chain
	dirtyInsertAppend    set.Set[string]

	chainRefCounts map[string]int
	dirtyChains    set.Set[string]

	inSyncWithDataPlane bool

	chainToDataplaneHashes map[string][]string
	// chainToDataplaneNumbers は chainToDataplaneHashes と同じ並びで、各ルールの実際の IPFW の
	// ルール番号を持つ。置き換え・削除は位置から番号を計算せず、この番号で行う
	// （末尾の return は開始番号+RULE_BUF-1 にあり、位置と番号が対応しないため）。
	chainToDataplaneNumbers map[string][]int
	// lastReadNumbers は readHashesAndRulesFrom が最後に読んだ番号（loadDataplaneState で採用する）。
	lastReadNumbers map[string][]int

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

	peakIpfwSaveTime    time.Duration
	peakIpfwRestoreTime time.Duration

	calicoIpfwLock sync.Locker

	lockTimeout       time.Duration
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
	hashCommentRegexp := regexp.MustCompile(`//\s*` + regexp.QuoteMeta(hashPrefix) + `([a-zA-Z0-9_-]+)`)
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

	inserts := map[string][]Rule{}
	appends := map[string][]Rule{}
	dirtyInsertAppend := set.New[string]()
	refcounts := map[string]int{}
	for _, kernelChain := range tableToKernelChains[name] {
		inserts[kernelChain] = []Rule{}
		appends[kernelChain] = []Rule{}
		dirtyInsertAppend.Add(kernelChain)
		// Kernel chains are referred to by definition.
		refcounts[kernelChain] += 1
	}

	var insertMode string
	switch options.InsertMode {
	case "", "insert":
		insertMode = "insert"
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
		chainToInsertedRules:   inserts,
		chainToAppendedRules:   appends,
		dirtyInsertAppend:      dirtyInsertAppend,
		chainNameToChain:       map[string]*Chain{},
		chainRefCounts:         refcounts,
		dirtyChains:            set.New[string](),
		chainToDataplaneHashes: map[string][]string{},
		chainToDataplaneNumbers: map[string][]int{},
		lastReadNumbers:        map[string][]int{},
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

// Chainへのルール追加
// ・chainToAppendedRulesの更新
func (t *RuleSet) InsertOrAppendRules(chainName string, rules []Rule) {
	/*
	t.logCxt.WithField("chainName", chainName).Debug("Updating rule insertions")
	// 古いルールの取得
	oldRules := t.chainToInsertedRules[chainName]
	// 新しいルールを保存
	t.chainToInsertedRules[chainName] = rules
	// ルール数の更新
	numRulesDelta := len(rules) - len(oldRules)
	t.gaugeNumRules.Add(float64(numRulesDelta))
	// 次回Apply時に反映するためのマーキング
	t.dirtyInsertAppend.Add(chainName)

	// 参照数などの管理
	t.maybeIncrefReferredChains(chainName, rules)
	t.maybeDecrefReferredChains(chainName, oldRules)

	// 再チェックと更新を促すためのキャシュ無効化
	t.InvalidateDataplaneCache("insertion")
	*/
	t.AppendRules(chainName, rules)
}

// Chainへのルール追加（Append版）
// 使うmapが違う
func (t *RuleSet) AppendRules(chainName string, rules []Rule) {
	t.logCxt.WithField("chainName", chainName).Debug("Updating rule appends")
	oldRules := t.chainToAppendedRules[chainName]
	t.chainToAppendedRules[chainName] = rules
	numRulesDelta := len(rules) - len(oldRules)
	t.gaugeNumRules.Add(float64(numRulesDelta))
	t.dirtyInsertAppend.Add(chainName)

	t.maybeIncrefReferredChains(chainName, rules)
	t.maybeDecrefReferredChains(chainName, oldRules)

	t.InvalidateDataplaneCache("insertion")
}

func (t *RuleSet) UpdateChains(chains []*Chain) {
	for _, chain := range chains {
		t.UpdateChain(chain)
	}
}

// Chainの登録
// ・chainNameToChainの登録
// ・dirtyChainsへの登録
func (t *RuleSet) UpdateChain(chain *Chain) {
	t.logCxt.WithField("chainName", chain.Name).Debug("Adding chain to available set.")
	oldNumRules := 0

	t.maybeIncrefReferredChains(chain.Name, chain.Rules)
	if oldChain := t.chainNameToChain[chain.Name]; oldChain != nil {
		oldNumRules = len(oldChain.Rules)
		t.maybeDecrefReferredChains(chain.Name, oldChain.Rules)
	}

	// chainNameToChainの登録
	t.chainNameToChain[chain.Name] = chain
	// ChainNameToChainの登録
	ChainNameToChain[chain.Name] = chain
	if chain.GetStartRuleNum() == 65535 {
		t.logCxt.WithField("chainName", chain.Name).Panic("Failed GetStartRuleNum")
	}
	numRulesDelta := len(chain.Rules) - oldNumRules
	t.gaugeNumRules.Add(float64(numRulesDelta))
	if t.chainIsReferenced(chain.Name) {
		// dirtyChainsへの登録
		t.dirtyChains.Add(chain.Name)

		t.InvalidateDataplaneCache("chain update")
	}
}

func (t *RuleSet) RemoveChains(chains []*Chain) {
	for _, chain := range chains {
		t.RemoveChainByName(chain.Name)
	}
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

func (t *RuleSet) chainIsReferenced(name string) bool {
	return t.chainRefCounts[name] > 0
}

func (t *RuleSet) maybeIncrefReferredChains(chainName string, rules []Rule) {
	if !t.chainIsReferenced(chainName) {
		return
	}
	for _, r := range rules {
		if ref, ok := r.Action.(Referrer); ok {
			t.increfChain(ref.ReferencedChain())
		}
	}
}

func (t *RuleSet) maybeDecrefReferredChains(chainName string, rules []Rule) {
	if !t.chainIsReferenced(chainName) {
		return
	}
	for _, r := range rules {
		if ref, ok := r.Action.(Referrer); ok {
			t.decrefChain(ref.ReferencedChain())
		}
	}
}

func (t *RuleSet) increfChain(chainName string) {
	log.WithField("chainName", chainName).Debug("Incref chain")
	t.chainRefCounts[chainName] += 1
	if t.chainRefCounts[chainName] == 1 {
		t.updateRateLimitedLog.WithField("chainName", chainName).Info("Chain became referenced, marking it for programming")
		t.dirtyChains.Add(chainName)
		if chain := t.chainNameToChain[chainName]; chain != nil {
			// Recursively incref chains that this chain refers to.  If
			// chain == nil then the chain is likely about to be added, in
			// which case we'll handle this whe the chain is added.
			t.maybeIncrefReferredChains(chainName, chain.Rules)
		}
	}
}

func (t *RuleSet) decrefChain(chainName string) {
	log.WithField("chainName", chainName).Debug("Decref chain")
	if t.chainRefCounts[chainName] == 1 {
		t.updateRateLimitedLog.WithField("chainName", chainName).Info("Chain no longer referenced, marking it for removal")
		if chain := t.chainNameToChain[chainName]; chain != nil {
			// Recursively decref chains that this chain refers to.  If
			// chain == nil then the chain has probably already been deleted
			// in which case we'll already have done the decrefs.
			t.maybeDecrefReferredChains(chainName, chain.Rules)
		}
		delete(t.chainRefCounts, chainName)
		t.dirtyChains.Add(chainName)
		return
	}

	// Chain still referenced, just decrement.
	t.chainRefCounts[chainName] -= 1
}

func (t *RuleSet) loadDataplaneState() {
	// Refresh the cache of feature data.
	t.featureDetector.RefreshFeatures()

	// Load the hashes from the dataplane.
	t.logCxt.Debug("Loading current ipfw state and checking it is correct.")
	t.opReporter.RecordOperation(fmt.Sprintf("resync-%v-v%d", t.Name, t.IPVersion))

	t.lastReadTime = t.timeNow()
	dataplaneHashes, dataplaneRules := t.getHashesAndRulesFromDataplane()

	// Check that the rules we think we've programmed are still there and mark any inconsistent
	// chains for refresh.
	for chainName, expectedHashes := range t.chainToDataplaneHashes {
		logCxt := t.logCxt.WithField("chainName", chainName)
		if t.dirtyChains.Contains(chainName) || t.dirtyInsertAppend.Contains(chainName) {
			// Already an update pending for this chain; no point in flagging it as
			// out-of-sync.
			logCxt.Debug("Skipping known-dirty chain")
			continue
		}
		dpHashes := dataplaneHashes[chainName]
		if !t.ourChainsRegexp.MatchString(chainName) {
			// Not one of our chains so it may be one that we're inserting rules into.
			insertedRules := t.chainToInsertedRules[chainName]
			// InsertOrAppendRules は AppendRules を使う（chainToAppendedRules に入る）ため、
			// 追加のルールも見る。見ないと、追加のルールしかないチェインが再同期のたびに不一致になる。
			if len(insertedRules) == 0 && len(t.chainToAppendedRules[chainName]) == 0 {
				// This chain shouldn't have any inserts, make sure that's the
				// case.  This case also covers the case where a chain was removed,
				// making dpHashes nil.
				dataplaneHasInserts := false
				for _, hash := range dpHashes {
					if hash != "" {
						dataplaneHasInserts = true
						break
					}
				}
				if dataplaneHasInserts {
					logCxt.WithField("actualRuleIDs", dpHashes).Warn(
						"Chain had unexpected inserts, marking for resync")
					t.dirtyInsertAppend.Add(chainName)
				}
				continue
			}

			// Re-calculate the expected rule insertions based on the current length
			// of the chain (since other processes may have inserted/removed rules
			// from the chain, throwing off the numbers).
			expectedHashes, _, _ = t.expectedHashesForInsertAppendChain(
				chainName,
				numEmptyStrings(dpHashes),
			)
			if diff := cmp.Diff(expectedHashes, dpHashes); diff != "" {
				fmt.Printf("[souma-log] len(diff)=%d\n", len(diff))
				fmt.Printf("[souma-log] as-v = %v\n", diff)
				fmt.Printf("[souma-log] as-s = %s\n", diff)
				fmt.Printf("[souma-log] as-q = %q\n", diff)
				fmt.Printf("[souma-log] mismatch (-expected +got):\n%s", diff)
			}
			if !reflect.DeepEqual(dpHashes, expectedHashes) {
				logCxt.WithFields(log.Fields{
					"expectedRuleIDs": expectedHashes,
					"actualRuleIDs":   dpHashes,
				}).Warn("Detected out-of-sync inserts, marking for resync")
				t.dirtyInsertAppend.Add(chainName)
			}
		} else {
			if diff := cmp.Diff(expectedHashes, dpHashes); diff != "" {
				fmt.Printf("[souma-log] len(diff)=%d\n", len(diff))
				fmt.Printf("[souma-log] as-v = %v\n", diff)
				fmt.Printf("[souma-log] as-s = %s\n", diff)
				fmt.Printf("[souma-log] as-q = %q\n", diff)
				fmt.Printf("[souma-log] mismatch (-expected +got):\n%s", diff)
			}
			// One of our chains, should match exactly.
			if !reflect.DeepEqual(dpHashes, expectedHashes) {
				logCxt.Warn("Detected out-of-sync Calico chain, marking for resync")
				t.dirtyChains.Add(chainName)
			}
		}
	}

	// Now scan for chains that shouldn't be there and mark for deletion.
	t.logCxt.Debug("Scanning for unexpected ipfw chains")
	for chainName, dataplaneHashes := range dataplaneHashes {
		logCxt := t.logCxt.WithField("chainName", chainName)
		if t.dirtyChains.Contains(chainName) || t.dirtyInsertAppend.Contains(chainName) {
			// Already an update pending for this chain.
			logCxt.Debug("Skipping known-dirty chain")
			continue
		}
		if _, ok := t.chainToDataplaneHashes[chainName]; ok {
			// Chain expected, we'll have checked its contents above.
			logCxt.Debug("Skipping expected chain")
			continue
		}
		if !t.ourChainsRegexp.MatchString(chainName) {
			// Non-calico chain that is not tracked in chainToDataplaneHashes. We
			// haven't seen the chain before and we haven't been asked to insert
			// anything into it.  Check that it doesn't have an rule insertions in it
			// from a previous run of Felix.
			for _, hash := range dataplaneHashes {
				if hash != "" {
					logCxt.Info("Found unexpected insert, marking for cleanup")
					t.dirtyInsertAppend.Add(chainName)
					break
				}
			}
			continue
		}
		// Chain exists in dataplane but not in memory, mark as dirty so we'll clean it up.
		logCxt.Info("Found unexpected chain, marking for cleanup")
		t.dirtyChains.Add(chainName)
	}

	t.logCxt.Debug("Finished loading ipfw state")
	t.chainToDataplaneHashes = dataplaneHashes
	t.chainToDataplaneNumbers = t.lastReadNumbers
	t.chainToFullRules = dataplaneRules
	t.inSyncWithDataPlane = true
}

func (t *RuleSet) expectedHashesForInsertAppendChain(
	chainName string,
	numNonCalicoRules int,
) (allHashes, ourInsertedHashes, ourAppendedHashes []string) {
	insertedRules := t.chainToInsertedRules[chainName]
	appendedRules := t.chainToAppendedRules[chainName]
	features := t.featureDetector.GetFeatures()
	if len(insertedRules) > 0 {
		ourInsertedHashes = CalculateRuleHashes(chainName, insertedRules, features)
	}
	if len(appendedRules) > 0 {
		// chainName to produce a unique hash in case append chain/rules are same
		// as insert chain/rules above.
		ourAppendedHashes = CalculateRuleHashes(chainName+"*append*", appendedRules, features)
	}
	allHashes = make([]string, len(ourInsertedHashes)+len(ourAppendedHashes)+numNonCalicoRules)
	offset := 0
	if t.insertMode == "append" {
		log.Debug("In append mode, returning our hashes at end.")
		offset = numNonCalicoRules
	}
	for i, hash := range ourInsertedHashes {
		allHashes[i+offset] = hash
	}

	offset = len(insertedRules) + numNonCalicoRules
	for i, hash := range ourAppendedHashes {
		allHashes[i+offset] = hash
	}
	return
}

func (t *RuleSet) getHashesAndRulesFromDataplane() (hashes map[string][]string, rules map[string][]string) {
	retries := 3
	retryDelay := 100 * time.Millisecond

	// Retry a few times before we panic.  This deals with any transient errors and it prevents
	// us from spamming a panic into the log when we're being gracefully shut down by a SIGTERM.
	for {
		t.onStillAlive()
		hashes, rules, err := t.attemptToGetHashesAndRulesFromDataplane()
		if err != nil {
			countNumSaveErrors.Inc()
			var stderr string
			if ee, ok := err.(*exec.ExitError); ok {
				stderr = string(ee.Stderr)
			}
			t.logCxt.WithError(err).WithField("stderr", stderr).Warnf("%s command failed", t.ipfwCmd)
			if retries > 0 {
				retries--
				t.timeSleep(retryDelay)
				retryDelay *= 2
			} else {
				t.logCxt.Panicf("%s command failed after retries", t.ipfwCmd)
			}
			continue
		}

		return hashes, rules
	}
}

func (t *RuleSet) attemptToGetHashesAndRulesFromDataplane() (hashes map[string][]string, rules map[string][]string, err error) {
	startTime := t.timeNow()
	defer func() {
		saveDuration := t.timeNow().Sub(startTime)
		t.peakIpfwSaveTime = t.peakIpfwSaveTime * 99 / 100
		if saveDuration > t.peakIpfwSaveTime {
			log.WithField("duration", saveDuration).Debug("Updating ipfw-save peak duration.")
			t.peakIpfwSaveTime = saveDuration
		}
	}()

	t.logCxt.Debugf("Starting %s", t.ipfwCmd)
	cmd := t.newCmd(t.ipfwCmd, "list")
	countNumSaveCalls.Inc()

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.WithError(err).Warnf("Failed to get stdout pipe for %s", t.ipfwCmd)
		return
	}
	err = cmd.Start()
	if err != nil {
		// Failed even before we started, close the pipe.  (This would normally be done
		// by Wait().
		log.WithError(err).Warnf("Failed to start %s", t.ipfwCmd)
		closeErr := stdout.Close()
		if closeErr != nil {
			log.WithError(closeErr).Warn("Error closing stdout after Start() failed.")
		}
		return
	}
	hashes, rules, err = t.readHashesAndRulesFrom(stdout)
	if err != nil {
		// In case readHashesAndRulesFrom() returned due to an error that didn't cause the
		// process to exit, kill it now.
		log.WithError(err).Warnf("Killing %s process after a failure", t.ipfwCmd)
		killErr := cmd.Kill()
		if killErr != nil {
			// If we don't know what state the process is in, we can't Wait() on it.
			log.WithError(killErr).Panicf(
				"Failed to kill %s process after failure.", t.ipfwCmd)
		}
	}
	waitErr := cmd.Wait()
	if waitErr != nil {
		log.WithError(waitErr).Warn("ipfw save failed")
		if err == nil {
			err = waitErr
		}
	}
	return
}

// TODO
// 独自実装
// ipfw 出力例:
// "00100 count // ChainName"
// "00101 allow ip from any to any // cali:OUTPUT:spH8qYYv24LlK31x"
func (t *RuleSet) readHashesAndRulesFrom(r io.ReadCloser) (hashes map[string][]string, rules map[string][]string, err error) {
	hashes = make(map[string][]string)
	rules = make(map[string][]string)
	numbers := make(map[string][]int)
	scanner := bufio.NewScanner(r)

	chainHasCalicoRule := set.New[string]()

	//debug := log.GetLevel() >= log.DebugLevel

	for scanner.Scan(){
		// 1行ずつ取得
		line := scanner.Bytes()

		// ルールを取得
		// appendRegexp = "// cali:([^:]+):(.+)"
		captures := appendRegexp.FindSubmatch(line)
		if captures == nil {
			t.logCxt.Debug("Not an append, skipping")
			continue
		}
		commentChainName := string(captures[1])
		if !strings.Contains(commentChainName, tablePrefix(t.Name)) {
			//logCxt.Debug("Table hasn't Chain")
			continue
		}
		// InsertOrAppendRules で追加したルールのハッシュは "<チェイン名>*append*" で計算される
		// （expectedHashesForInsertAppendChain）。メモリ上では "<チェイン名>" で管理しているため、
		// 読み直した結果も "<チェイン名>" に揃える（ハッシュの値は "*append*" 付きのまま）。
		chainName := strings.TrimSuffix(commentChainName, "*append*")

		hash := ""
		if captures != nil {
			hash = string(fmt.Sprintf("%s:%s", captures[1], captures[2]))
			chainHasCalicoRule.Add(chainName)
		}
		hashes[chainName] = append(hashes[chainName], hash)
		// 実際のルール番号を、ハッシュと同じ並びで記録する（読めない場合は -1）。
		num, ok := ExtractLeadingRuleNumber(string(line))
		if !ok {
			num = -1
		}
		numbers[chainName] = append(numbers[chainName], num)

		if !t.ourChainsRegexp.MatchString(chainName) {
			// Only store the full rule for Calico rules. Otherwise, we just use the placeholder "-".
			fullRule := "-"
			if captures := t.hashCommentRegexp.FindSubmatch(line); captures != nil {
				fullRule = string(line)
			}

			rules[chainName] = append(rules[chainName], fullRule)
		}
	}
	if scanner.Err() != nil {
		log.WithError(scanner.Err()).Error("Failed to read hashes from dataplane")
		return nil, nil, scanner.Err()
	}

	for chainName := range rules {
		if !chainHasCalicoRule.Contains(chainName) {
			delete(rules, chainName)
		}
	}


	t.logCxt.Debugf("Read hashes from dataplane: %#v", hashes)
	t.logCxt.Debugf("Read rules from dataplane: %#v", rules)
	t.lastReadNumbers = numbers
	return hashes, rules, nil
}

func tablePrefix(tableName string) string {
	switch tableName {
	case "filter":
		return "F-"
	case "raw":
		return "R-"
	case "mangle":
		return "M-"
	case "nat":
		return "N-"
	default:
		log.Panic("tablePrefix failed")
		return "ERROR"
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

func (t *RuleSet) Apply() (rescheduleAfter time.Duration) {
	now := t.timeNow()
	defer func() {
		if time.Since(now) > time.Second {
			log.WithFields(log.Fields{
				"applyTime":      time.Since(now),
				"reasonForApply": t.reason,
			}).Info("Updating ipfw took >1s")
		}
	}()
	lastReadToNow := now.Sub(t.lastReadTime)
	invalidated := false
	if t.refreshInterval > 0 && lastReadToNow > t.refreshInterval {
		t.InvalidateDataplaneCache("refresh timer")
		invalidated = true
	}
	for t.postWriteInterval != 0 &&
		t.postWriteInterval < time.Hour &&
		!now.Before(t.lastWriteTime.Add(t.postWriteInterval)) {

		t.postWriteInterval *= 2
		t.logCxt.WithField("newPostWriteInterval", t.postWriteInterval).Debug("Updating post-write interval")
		if !invalidated {
			t.InvalidateDataplaneCache("post update")
			invalidated = true
		}
	}

	retries := 10
	backoffTime := 1 * time.Millisecond
	failedAtLeastOnce := false
	for {
		if !t.inSyncWithDataPlane {
			t.loadDataplaneState()
		}
		t.onStillAlive()

		if err := t.applyUpdates(); err != nil {
			if retries > 0 {
				retries--
				t.logCxt.WithError(err).Warn("Failed to program ipfw, will retry")
				t.timeSleep(backoffTime)
				backoffTime *= 2
				t.logCxt.WithError(err).Warn("Retrying...")
				failedAtLeastOnce = true
				continue
			} else {
				t.logCxt.WithError(err).Error("Failed to program ipfw, loading diags before panic.")
				cmd := t.newCmd(t.ipfwCmd, "list")
				output, err2 := cmd.Output()
				if err2 != nil {
					t.logCxt.WithError(err2).Error("Failed to load ipfw state")
				} else {
					t.logCxt.WithField("ipfwState", string(output)).Error("Current state of ipfw")
				}
				t.logCxt.WithError(err).Panic("Failed to program ipfw, giving up after retries")
			}
		}
		if failedAtLeastOnce {
			t.logCxt.Warn("Succeeded after retry.")
		}
		break
	}

	t.gaugeNumChains.Set(float64(len(t.chainRefCounts)))

	if t.refreshInterval > 0 {
		lastReadToNow = now.Sub(t.lastReadTime)
		rescheduleAfter = t.refreshInterval - lastReadToNow
	}
	if t.postWriteInterval < time.Hour {
		postWriteReached := t.lastWriteTime.Add(t.postWriteInterval).Sub(now)
		if postWriteReached <= 0 {
			rescheduleAfter = 1 * time.Millisecond
		} else if t.refreshInterval <= 0 || postWriteReached < rescheduleAfter {
			rescheduleAfter = postWriteReached
		}
	}

	return
}

func (t *RuleSet) applyUpdates() error {
	// If needed, detect the dataplane features.
	features := t.featureDetector.GetFeatures()

	// Build up the ipfw-restore input in an in-memory buffer.  This allows us to log out the exact input after
	// a failure, which has proven to be a very useful diagnostic tool.
	buf := &t.restoreInputBuffer
	buf.Reset() // Defensive.

	// ipfw-restore commands live in per-table transactions.
	buf.StartTransaction(t.Name)

	// Make a pass over the dirty chains and generate a forward reference for any that we're about to update.
	// Writing a forward reference ensures that the chain exists and that it is empty.
	t.dirtyChains.Iter(func(chainName string) error {
		chainNeedsToBeFlushed := false
		if _, present := t.desiredStateOfChain(chainName); !present {
			// About to delete this chain, flush it first to sever dependencies.
			chainNeedsToBeFlushed = true
		} else if _, ok := t.chainToDataplaneHashes[chainName]; !ok {
			// Chain doesn't exist in dataplane, mark it for creation.
			chainNeedsToBeFlushed = true
		}
		if chainNeedsToBeFlushed {
			buf.WriteForwardReference(chainName)
		}
		return nil
	})

	// Make a second pass over the dirty chains.  This time, we write out the rule changes.
	//
	// IPFW のルール番号は削除しても詰まらず、ipfw delete <番号> はその番号のルールをすべて消す
	// （ip_fw_sockopt.c の delete_range）。そのため、位置から番号を計算して置き換えるのではなく、
	// 次の2段階で更新する。
	//   1. すべてのチェインについて、消す番号を先に集める。
	//      - 本体のチェイン: ハッシュが変わった位置・なくなった位置の実際の番号
	//        （chainToDataplaneNumbers。読み直したときに ipfw list から記録したもの）
	//      - 不要になったチェイン: 記録しているすべての番号
	//      - 挿入・追加のルール: ずれていれば記録しているすべての番号
	//   2. 削除をすべて書いてから、追加を書く。
	//      ハッシュが変わった位置・増えた位置のルールに加えて、1. で消した番号に置かれていた
	//      ルール（ほかのチェインのものを含む）も入れ直す。
	// 削除を先にまとめて書くので、同じ番号を削除と追加の両方で使っても正しく揃う
	// （末尾の return が開始番号+RULE_BUF-1 にあることや、前回の実行で残った同じ番号のルールにも対応する）。
	// 削除と追加は1つのスクリプトで順に実行するため、iptables-restore のような一括の切り替えではない。
	newHashes := map[string][]string{}
	newNumbers := map[string][]int{}

	// 記録した番号（実際に ipfw list に出ていた番号、または前回の反映で入れた番号）の削除は、
	// 失敗したら反映全体を失敗にする（set -e）。番号が分からないときに区画全体を消す場合だけは、
	// その番号にルールがないことがあるので失敗を許す（mayBeAbsent）。
	deleted := map[int]bool{}
	mayBeAbsent := map[int]bool{}
	var deleteOrder []int
	addDelete := func(n int) {
		delete(mayBeAbsent, n) // 記録した番号として消すので、失敗を許さない
		if !deleted[n] {
			deleted[n] = true
			deleteOrder = append(deleteOrder, n)
		}
	}
	addDeleteMayBeAbsent := func(n int) {
		if !deleted[n] {
			deleted[n] = true
			mayBeAbsent[n] = true
			deleteOrder = append(deleteOrder, n)
		}
	}

	// 1a. 本体のチェイン（更新・作成・削除）
	type pendingChain struct {
		chain          *Chain
		previousHashes []string
		currentHashes  []string
		currentNumbers []int
	}
	pendingChains := map[string]*pendingChain{}
	t.dirtyChains.Iter(func(chainName string) error {
		previousHashes := t.chainToDataplaneHashes[chainName]
		previousNumbers := t.chainToDataplaneNumbers[chainName]

		chain, ok := t.desiredStateOfChain(chainName)
		if !ok {
			// Chain deletion.  記録しているすべての番号を消す。
			for i, n := range previousNumbers {
				if n > 0 {
					addDelete(n)
				} else {
					t.logCxt.WithFields(log.Fields{
						"chainName": chainName,
						"position":  i,
					}).Warn("Unknown rule number in dataplane; cannot delete this rule")
				}
			}
			newHashes[chainName] = nil
			newNumbers[chainName] = nil
			return nil
		}

		// Chain update or creation.  Scan the chain against its previous hashes.
		currentHashes := chain.RuleHashes(features)
		currentNumbers := make([]int, len(chain.Rules))
		for i, rule := range chain.Rules {
			currentNumbers[i] = int(rule.Number)
		}
		newHashes[chainName] = currentHashes
		newNumbers[chainName] = currentNumbers
		pendingChains[chainName] = &pendingChain{
			chain:          chain,
			previousHashes: previousHashes,
			currentHashes:  currentHashes,
			currentNumbers: currentNumbers,
		}

		for i := range previousHashes {
			if i < len(currentHashes) && previousHashes[i] == currentHashes[i] {
				continue
			}
			if i < len(previousNumbers) && previousNumbers[i] > 0 {
				addDelete(previousNumbers[i])
			} else {
				// 番号が分からない場合は、このチェインの区画全体を消してから入れ直す。
				t.logCxt.WithField("chainName", chainName).Warn(
					"Unknown rule number in dataplane; rewriting the whole chain block")
				for n := int(chain.GetStartRuleNum()); n < int(chain.GetStartRuleNum())+RULE_BUF; n++ {
					addDeleteMayBeAbsent(n)
				}
				break
			}
		}
		return nil // Delay clearing the set until we've programmed ipfw.
	})

	// Make a copy of our full rules map and keep track of all changes made while processing dirtyInsertAppend.
	// When we've successfully updated ipfw, we'll update our cache of chainToFullRules with this map.
	newChainToFullRules := map[string][]string{}
	for chain, rules := range t.chainToFullRules {
		newChainToFullRules[chain] = make([]string, len(rules))
		copy(newChainToFullRules[chain], rules)
	}

	// 1b. 挿入・追加のルール（振り分けの区画 1〜49 から各チェインを呼ぶルール）
	// Now calculate ipfw updates for our inserted and appended rules, which are used to hook top-level chains.
	type pendingInsertAppend struct {
		newRules              []string
		newInsertedRuleHashes []string
		newAppendedRuleHashes []string
	}
	pendingInsertAppends := map[string]*pendingInsertAppend{}
	var deleteRenderingErr error
	t.dirtyInsertAppend.Iter(func(chainName string) error {
		previousHashes := t.chainToDataplaneHashes[chainName]
		newRules := newChainToFullRules[chainName]

		// Calculate the hashes for our inserted and appended rules.
		numNonCalicoRules := numEmptyStrings(previousHashes)
		newChainHashes, newInsertedRuleHashes, newAppendedRuleHashes := t.expectedHashesForInsertAppendChain(
			chainName, numNonCalicoRules)

		if reflect.DeepEqual(newChainHashes, previousHashes) {
			// Chain is in sync, skip to next one.
			return nil
		}

		// For simplicity, if we've discovered that we're out-of-sync, remove all our
		// rules from this chain, then re-insert/re-append them below.
		// 削除は、読み直したときに記録した実際の番号で行う（位置からは計算しない）。
		previousNumbers := t.chainToDataplaneNumbers[chainName]
		for i := 0; i < len(previousHashes); i++ {
			if previousHashes[i] != "" {
				if i >= len(previousNumbers) || previousNumbers[i] <= 0 {
					deleteRenderingErr = fmt.Errorf(
						"unknown rule number for rule %d in %q; cannot delete it safely", i, chainName)
					return set.StopIteration
				}
				addDelete(previousNumbers[i])
			}
		}

		// 新しいルールの番号を、ハッシュと同じ並びで記録する（Calico 以外のルールの位置は -1）。
		insertedRules := t.chainToInsertedRules[chainName]
		appendedRules := t.chainToAppendedRules[chainName]
		numbers := make([]int, len(newChainHashes))
		for i := range numbers {
			numbers[i] = -1
		}
		offset := 0
		if t.insertMode == "append" {
			offset = numNonCalicoRules
		}
		for i, rule := range insertedRules {
			numbers[i+offset] = int(rule.Number)
		}
		offset = len(insertedRules) + numNonCalicoRules
		for i, rule := range appendedRules {
			numbers[i+offset] = int(rule.Number)
		}
		for _, rule := range append(append([]Rule{}, insertedRules...), appendedRules...) {
			if rule.Number == 0 {
				// 番号 0 は ipfw add で自動採番になり、記録した番号と一致しなくなる。
				deleteRenderingErr = fmt.Errorf(
					"inserted/appended rule in %q has no rule number", chainName)
				return set.StopIteration
			}
		}

		// Go over our slice of "new" rules and create a copy of the slice with just the rules we didn't empty out.
		copyOfNewRules := []string{}
		for _, rule := range newRules {
			if rule != "" {
				copyOfNewRules = append(copyOfNewRules, rule)
			}
		}
		pendingInsertAppends[chainName] = &pendingInsertAppend{
			newRules:              copyOfNewRules,
			newInsertedRuleHashes: newInsertedRuleHashes,
			newAppendedRuleHashes: newAppendedRuleHashes,
		}
		newHashes[chainName] = newChainHashes
		newNumbers[chainName] = numbers

		return nil // Delay clearing the set until we've programmed ipfw.
	})
	// If rendering a delete by line number reached an unexpected state, error out so applyUpdates() can be retried.
	if deleteRenderingErr != nil {
		return deleteRenderingErr
	}

	// 2. 削除をすべて書いてから、追加を書く。
	for _, n := range deleteOrder {
		buf.WriteLine(renderDeleteNumberLine(n, mayBeAbsent[n]))
	}

	// 2a. 本体のチェイン: 変わった位置・増えた位置と、消した番号に置かれていたルールを追加する。
	for chainName, p := range pendingChains {
		for i := range p.currentHashes {
			changed := i >= len(p.previousHashes) || p.previousHashes[i] != p.currentHashes[i]
			if changed || deleted[p.currentNumbers[i]] {
				prefixFrag := t.commentFrag(p.currentHashes[i])
				buf.WriteLine(p.chain.Rules[i].RenderAppend(chainName, prefixFrag, features))
			}
		}
	}

	// 2b. 今回更新しないチェインでも、消した番号にルールが置かれていれば入れ直す
	// （前回の実行で残ったチェインが同じ番号を使っていた場合など）。
	// 更新しないチェインはハッシュが一致しているので、i 番目の記録とルールは対応している。
	if len(deleted) > 0 {
		for chainName, numbers := range t.chainToDataplaneNumbers {
			if _, ok := pendingChains[chainName]; ok {
				continue
			}
			if t.dirtyChains.Contains(chainName) || t.dirtyInsertAppend.Contains(chainName) {
				continue
			}
			chain, ok := t.desiredStateOfChain(chainName)
			if !ok {
				continue
			}
			hashes := t.chainToDataplaneHashes[chainName]
			for i, n := range numbers {
				if !deleted[n] || i >= len(chain.Rules) || i >= len(hashes) {
					continue
				}
				t.logCxt.WithFields(log.Fields{
					"chainName":  chainName,
					"ruleNumber": n,
				}).Info("Re-adding rule whose number was deleted by another chain update")
				buf.WriteLine(chain.Rules[i].RenderAppend(chainName, t.commentFrag(hashes[i]), features))
			}
		}
	}

	// 2c. 挿入・追加のルール
	for chainName, p := range pendingInsertAppends {
		newRules := p.newRules

		// Add inserted rules if there is any
		rules := t.chainToInsertedRules[chainName]
		if len(rules) > 0 {
			t.logCxt.Debug("Rendering append rules.")
			insertRuleLines := make([]string, len(rules))
			for i := 0; i < len(rules); i++ {
				prefixFrag := t.commentFrag(p.newInsertedRuleHashes[i])
				line := rules[i].RenderAppend(chainName, prefixFrag, features)
				buf.WriteLine(line)
				insertRuleLines[i] = line
			}
			newRules = append(newRules, insertRuleLines...)
		}

		// Add appended rules if there is any
		rules = t.chainToAppendedRules[chainName]
		if len(rules) > 0 {
			t.logCxt.Debug("Rendering specific append rules.")
			appendRuleLines := make([]string, len(rules))
			for i := 0; i < len(rules); i++ {
				prefixFrag := t.commentFrag(p.newAppendedRuleHashes[i])
				line := rules[i].RenderAppend(chainName, prefixFrag, features)
				buf.WriteLine(line)
				appendRuleLines[i] = line
			}
			newRules = append(newRules, appendRuleLines...)
		}

		newChainToFullRules[chainName] = newRules
	}

	buf.EndTransaction()

	if buf.Empty() {
		t.logCxt.Debug("Update ended up being no-op, skipping call to ip(6)tables-restore.")
	} else {
		// Get the contents of the buffer ready to send to ipfw-restore.  Warning: for perf, this is directly
		// accessing the buffer's internal array; don't touch the buffer after this point.
		t.opReporter.RecordOperation(fmt.Sprintf("update-%v-v%d", t.Name, t.IPVersion))

		if err := t.execIpfwRestore(buf); err != nil {
			// スクリプトは途中の行で止まるため、データプレーンは一部だけ変わっている。
			// 本家（Table.applyUpdates）と同じく、次の試行の前に読み直して差分を取り直す。
			// キャッシュ（chainToDataplaneHashes など）は更新しない。
			t.inSyncWithDataPlane = false
			return fmt.Errorf("writing out buffer: %w", err)
		}

		t.lastWriteTime = t.timeNow()
		t.postWriteInterval = t.initialPostWriteInterval
	}

	if t.postWriteInterval != 0 {
		// If ipfw-save/restore is taking a long time (as measured by
		// the peakIpfwX fields), make sure that we don't try to
		// recheck the ipfw state too soon.
		dynamicMinPostWriteInterval := (t.peakIpfwSaveTime + t.peakIpfwRestoreTime) * 2
		if t.postWriteInterval < dynamicMinPostWriteInterval {
			log.WithFields(log.Fields{
				"dynamicMin":  dynamicMinPostWriteInterval,
				"peakSave":    t.peakIpfwSaveTime,
				"peakRestore": t.peakIpfwRestoreTime,
			}).Debug(
				"Post write interval shorter than time to read/write ipfw, applying dynamic minimum.")
			t.postWriteInterval = dynamicMinPostWriteInterval
		}
	}

	// Now we've successfully updated ipfw, clear the dirty sets.  We do this even if we
	// found there was nothing to do above, since we may have found out that a dirty chain
	// was actually a no-op update.
	t.dirtyChains = set.New[string]()
	t.dirtyInsertAppend = set.New[string]()

	// Store off the updates.
	for chainName, hashes := range newHashes {
		if hashes == nil {
			delete(t.chainToDataplaneHashes, chainName)
		} else {
			t.chainToDataplaneHashes[chainName] = hashes
		}
	}
	for chainName, numbers := range newNumbers {
		if numbers == nil {
			delete(t.chainToDataplaneNumbers, chainName)
		} else {
			t.chainToDataplaneNumbers[chainName] = numbers
		}
	}
	t.chainToFullRules = newChainToFullRules

	return nil
}

const (
	RESTORE_DIR = "/tmp/calico/"
	RESTORE_IPFW = RESTORE_DIR+"ipfw_rules"
)

var countIpfwRestore int = 0

// TODO
// execIptablesRestoreと見比べる
func (r *RuleSet) execIpfwRestore(buf *RestoreInputBuilder) error {
	if err := os.MkdirAll(RESTORE_DIR, 0755); err != nil {
		return fmt.Errorf("MkdirAll failed: %v", err)
	}

	input := buf.GetBytesAndReset()

	path := fmt.Sprintf("%s%d.sh",RESTORE_IPFW, countIpfwRestore)
	if err := BytesToRestoreFile(input, path); err != nil {
		return fmt.Errorf("BytesToRestoreFile failed: %v", err)
	}

	countIpfwRestore++

	// スクリプトは set -e で、失敗した行で止まり 0 以外で終了する（RestoreScriptHeader）。
	// 失敗したときは ipfw の出力（標準エラーを含む）をログとエラーに含める。
	if out, err := exec.Command(path).CombinedOutput(); err != nil {
		output := strings.TrimSpace(string(out))
		r.logCxt.WithError(err).WithFields(log.Fields{
			"script": path,
			"output": output,
		}).Warn("Failed to apply ipfw rules")
		return fmt.Errorf("exec %s failed: %v: %s", path, err, output)
	}
	return nil
}

func (t *RuleSet) desiredStateOfChain(chainName string) (chain *Chain, present bool) {
	if !t.chainIsReferenced(chainName) {
		return
	}
	chain, present = t.chainNameToChain[chainName]
	if present {
		return
	}
	return t.placeholderChain(chainName)
}

// placeholderChain は、参照されているがまだルールが登録されていないチェインの代わりに置く
// 空のチェイン（開始番号の count と、開始番号+RULE_BUF-1 の return だけ）を返す。
//
// IPFW の call / skipto は番号への移動で、移動先の番号にルールがなければ、それより大きい番号の
// 最初のルールへ進む（ipfw(8)）。参照先のチェインがないと次のチェインの区画を評価してしまうため、
// 本体が登録されるまで（または参照がなくなるまで）空のチェインを置いて、すぐに戻るようにする。
// 番号が決まっているチェイン（ChainNameToChain にあるもの）で、この表のものだけを対象にする。
func (t *RuleSet) placeholderChain(chainName string) (*Chain, bool) {
	if !strings.HasPrefix(chainName, "cali-"+tablePrefix(t.Name)) {
		return nil, false
	}
	known, ok := ChainNameToChain[chainName]
	if !ok || known.Number == 0 {
		return nil, false
	}
	c := &Chain{Name: chainName, Number: known.Number}
	if err := c.Organize(); err != nil {
		t.logCxt.WithError(err).WithField("chainName", chainName).Warn("Failed to build placeholder chain")
		return nil, false
	}
	return c, true
}

// renderDeleteNumberLine は、番号を指定してルールを消す行を返す。
// 通常は失敗をそのまま返す（set -e でスクリプトが止まる）。mayBeAbsent のとき
// （番号が分からず区画全体を消す場合）だけ、ルールがない番号の失敗を許す。
// ipfw の delete は、ルールがない番号と、それ以外の失敗（権限など）を終了状態で区別しないため、
// 区画全体の削除では、それ以外の失敗も後続の追加の失敗として検出する。
func renderDeleteNumberLine(ruleNum int, mayBeAbsent bool) string {
	if mayBeAbsent {
		return fmt.Sprintf("ipfw -q delete %d 2>/dev/null || true", ruleNum)
	}
	return fmt.Sprintf("ipfw -q delete %d", ruleNum)
}

func (t *RuleSet) commentFrag(hash string) string {
	return fmt.Sprintf("// %s%s", t.hashCommentPrefix, hash)
}

// renderDeleteByIndexLine produces a delete line by rule number. This function is used for cali chains.
func (t *RuleSet) renderDeleteByIndexLine(chainName string, ruleNum int) string {
	chain, ok := ChainNameToChain[chainName]
	if !ok {
		t.logCxt.Panic("ChainNameToChain Failed")
	}
	chainNum := chain.GetStartRuleNum()
	target := int(chainNum) + ruleNum -1
	return fmt.Sprintf("ipfw delete %d", target)
}

// renderDeleteByValueLine produces a delete line by the full rule at the given rule number. This function is
// used for non-Calico chains.
func (t *RuleSet) renderDeleteByValueLine(chainName string, ruleNum int) (string, error) {
	/*
	// For non-cali chains, get the rule by number but delete using the full rule instead of rule number.
	rules, ok := t.chainToFullRules[chainName]
	if !ok || ruleNum >= len(rules) {
		return "", fmt.Errorf("Rendering delete for nonexistent rule: Rule %d in %q", ruleNum, chainName)
	}

	rule := rules[ruleNum]
	target, ok := extractLeadingRuleNumber(rule)
	if !ok {
		return "", fmt.Errorf("Failed extractLeadingRuleNumber: Rule %d in %q", ruleNum, chainName)
	}

	return fmt.Sprintf("ipfw delete %d", target), nil
	*/
	chain, ok := ChainNameToChain[chainName]
	if !ok {
		//t.logCxt.Panic("ChainNameToChain Failed")
		return "", fmt.Errorf("ChainNameToChain failed: %s", chainName)
	}
	chainNum := chain.GetStartRuleNum()
	target := int(chainNum) + ruleNum -1
	return fmt.Sprintf("ipfw delete %d", target), nil
}

var leadingRuleNum = regexp.MustCompile(`^\s*(\d+)`)

// 先頭の数字を int で返す（ゼロ埋めは失われる）
func ExtractLeadingRuleNumber(line string) (int, bool) {
	m := leadingRuleNum.FindStringSubmatch(line)
	if m == nil {
		return -1, false
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return -1, false
	}
	return n, true
}

func CalculateRuleHashes(chainName string, rules []Rule, features *environment.Features) []string {
	// 挿入・追加のルールは呼び出し側が番号を決めて渡すので、Organize() はしない。
	// Organize() すると、"<チェイン名>*append*" という名前のチェインに新しい区画が割り当てられ
	// （ChainNameToChain に登録される）、先頭の count と末尾の return の分だけハッシュが増えて、
	// 実際に入れたルールのハッシュと並びが合わなくなる。
	chain := &Chain{
		Name: chainName,
		Rules: rules,
	}
	return chain.RuleHashes(features)
}

func numEmptyStrings(strs []string) int {
	count := 0
	for _, s := range strs {
		if s == "" {
			count++
		}
	}
	return count
}

// NoopTable fulfils the Table interface but does nothing.
type NoopRuleSet struct{}

func NewNoopRuleSet() *NoopRuleSet {
        return new(NoopRuleSet)
}

func (t *NoopRuleSet) Name() string                                       { return "" }
func (t *NoopRuleSet) IPVersion() uint8                                   { return 0 }
func (t *NoopRuleSet) InsertOrAppendRules(chainName string, rules []Rule) {}
func (t *NoopRuleSet) AppendRules(chainName string, rules []Rule)         {}
func (t *NoopRuleSet) UpdateChain(chain *Chain)                           {}
func (t *NoopRuleSet) UpdateChains([]*Chain)                              {}
func (t *NoopRuleSet) RemoveChains([]*Chain)                              {}
func (t *NoopRuleSet) RemoveChainByName(name string)                      {}
func (t *NoopRuleSet) InvalidateDataplaneCache(reason string)             {}
func (t *NoopRuleSet) Apply() time.Duration                               { return 0 }
