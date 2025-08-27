//go:build freebsd

package ipfw

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"regexp"
	"sync"
	"strings"
	"reflect"
	"os"
	"os/exec"
	"time"
	"io"

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

var ChainNameToChainNum map[string]uint16

func init() {
	ChainNameToChainNum = make(map[string]uint16)

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

	peakIpfwSaveTime    time.Duration
	peakIpfwRestoreTime time.Duration

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

	appends := map[string][]Rule{}
	inserts := map[string][]Rule{}
	dirtyAppend := set.New[string]()
	refcounts := map[string]int{}
	appends["all"] = []Rule{}
	dirtyAppend.Add("all")
	refcounts["all"] += 1

	insertMode := "append"

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
		chainToInsertedRules:   inserts,
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

	ruleset.chainNameToChain["INPUT"] = &Chain{
		Name: "INPUT",
		Number: 10,
		Rules: []Rule{},
	}
	ruleset.chainNameToChain["OUTPUT"] = &Chain{
		Name: "OUTPUT",
		Number: 20,
		Rules: []Rule{},
	}
	ruleset.chainNameToChain["FORWARD"] = &Chain{
		Name: "FORWARD",
		Number: 30,
		Rules: []Rule{},
	}

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
		if t.dirtyChains.Contains(chainName) || t.dirtyAppend.Contains(chainName) {
			// Already an update pending for this chain; no point in flagging it as
			// out-of-sync.
			logCxt.Debug("Skipping known-dirty chain")
			continue
		}
		dpHashes := dataplaneHashes[chainName]
		if !t.ourChainsRegexp.MatchString(chainName) {
			// Not one of our chains so it may be one that we're inserting rules into.
			insertedRules := t.chainToInsertedRules[chainName]
			if len(insertedRules) == 0 {
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
					t.dirtyAppend.Add(chainName)
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
			if !reflect.DeepEqual(dpHashes, expectedHashes) {
				logCxt.WithFields(log.Fields{
					"expectedRuleIDs": expectedHashes,
					"actualRuleIDs":   dpHashes,
				}).Warn("Detected out-of-sync inserts, marking for resync")
				t.dirtyAppend.Add(chainName)
			}
		} else {
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
		if t.dirtyChains.Contains(chainName) || t.dirtyAppend.Contains(chainName) {
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
					t.dirtyAppend.Add(chainName)
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
	t.chainToFullRules = dataplaneRules
	t.inSyncWithDataPlane = true
}

func (t *RuleSet) expectedHashesForInsertAppendChain(
	chainName string,
	numNonCalicoRules int,
) (allHashes, ourInsertedHashes, ourAppendedHashes []string) {
	insertedRules := t.chainToInsertedRules[chainName]
	appendedRules := t.chainToAppendedRules[chainName]
	allHashes = make([]string, len(insertedRules)+len(appendedRules)+numNonCalicoRules)
	features := t.featureDetector.GetFeatures()
	if len(insertedRules) > 0 {
		ourInsertedHashes = CalculateRuleHashes(chainName, insertedRules, features)
	}
	if len(appendedRules) > 0 {
		// Add *append* to chainName to produce a unique hash in case append chain/rules are same
		// as insert chain/rules above.
		ourAppendedHashes = CalculateRuleHashes(chainName+"*appends*", appendedRules, features)
	}
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
	//outBytes, _ := io.ReadAll(stdout)
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

func (t *RuleSet) readHashesAndRulesFrom(r io.ReadCloser) (hashes map[string][]string, rules map[string][]string, err error) {
	hashes = make(map[string][]string)
	rules = make(map[string][]string)

	data, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, err
	}

	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		if line == "" {
			continue
		}

		// ipfw 出力例: "00100 allow ip from any to any // cali:forward:spH8qYYv24LlK31x"
		if !strings.Contains(line, "// cali:") {
			continue
		}

		parts := strings.SplitN(line, "// cali:", 2)
		if len(parts) != 2 {
			continue
		}
		ruleText := strings.TrimSpace(parts[0])
		meta := strings.TrimSpace(parts[1])

		// "forward:spH8qYYv24LlK31x" → chainName="forward", ruleID="spH8qYYv24LlK31x"
		metaParts := strings.SplitN(meta, ":", 2)
		chainName := "cali-unknown"
		if len(metaParts) >= 1 {
			chainName = "cali-" + metaParts[0]
		}

		// 保存
		rules[chainName] = append(rules[chainName], ruleText)

		h := sha1.Sum([]byte(ruleText))
		hashes[chainName] = append(hashes[chainName], hex.EncodeToString(h[:8]))
	}

	return hashes, rules, nil
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
				cmd := t.newCmd(t.ipfwCmd)
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
	newHashes := map[string][]string{}
	t.dirtyChains.Iter(func(chainName string) error {
		if chain, ok := t.desiredStateOfChain(chainName); ok {
			// Chain update or creation.  Scan the chain against its previous hashes
			// and replace/append/delete as appropriate.
			var previousHashes []string
			// In ipfw legacy mode, we compare the rules one by one and apply deltas rule by rule.
			previousHashes = t.chainToDataplaneHashes[chainName]

			currentHashes := chain.RuleHashes(features)
			newHashes[chainName] = currentHashes
			for i := 0; i < len(previousHashes) || i < len(currentHashes); i++ {
				var line string
				if i < len(previousHashes) && i < len(currentHashes) {
					// RenderReplace not supported
				} else if i < len(previousHashes) {
					// renderDeleteByIndexLine not supported
				} else {
					// currentHashes was longer.  Append.
					prefixFrag := t.commentFrag(currentHashes[i])
					chainPtr, ok := t.chainNameToChain[chainName]
					if !ok || chainPtr == nil {
						t.logCxt.WithField("chainName", chainName).Error("chainName not found or nil in chainNameToChain")
						continue
					}
					line = chain.Rules[i].RenderAppend(*chainPtr, prefixFrag)
				}
				buf.WriteLine(line)
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

	// Now calculate ipfw updates for our inserted and appended rules, which are used to hook top-level chains.
	var deleteRenderingErr error
	t.dirtyAppend.Iter(func(chainName string) error {
		previousHashes := t.chainToDataplaneHashes[chainName]
		newRules := newChainToFullRules[chainName]

		// Calculate the hashes for our inserted and appended rules.
		newChainHashes, newInsertedRuleHashes, newAppendedRuleHashes := t.expectedHashesForInsertAppendChain(
			chainName, numEmptyStrings(previousHashes))

		if reflect.DeepEqual(newChainHashes, previousHashes) {
			// Chain is in sync, skip to next one.
			return nil
		}

		// Go over our slice of "new" rules and create a copy of the slice with just the rules we didn't empty out.
		copyOfNewRules := []string{}
		for _, rule := range newRules {
			if rule != "" {
				copyOfNewRules = append(copyOfNewRules, rule)
			}
		}
		newRules = copyOfNewRules
		rules := t.chainToInsertedRules[chainName]
		insertRuleLines := make([]string, len(rules))

		// Add inserted rules if there is any
		if len(rules) > 0 {
			t.logCxt.Debug("Rendering append rules.")
			for i := 0; i < len(rules); i++ {
				prefixFrag := t.commentFrag(newInsertedRuleHashes[i])
				chainPtr, ok := t.chainNameToChain[chainName]
				if !ok || chainPtr == nil {
					t.logCxt.WithField("chainName", chainName).Error("chainName not found or nil in chainNameToChain")
					continue
				}
				line := rules[i].RenderAppend(*chainPtr, prefixFrag)
				buf.WriteLine(line)
				insertRuleLines[i] = line
			}
			newRules = append(newRules, insertRuleLines...)
		}

		// Add appended rules if there is any
		rules = t.chainToAppendedRules[chainName]
		appendRuleLines := make([]string, len(rules))

		if len(rules) > 0 {
			t.logCxt.Debug("Rendering specific append rules.")
			for i := 0; i < len(rules); i++ {
				prefixFrag := t.commentFrag(newAppendedRuleHashes[i])
				chainPtr, ok := t.chainNameToChain[chainName]
				if !ok || chainPtr == nil {
					t.logCxt.WithField("chainName", chainName).Error("chainName not found or nil in chainNameToChain")
					continue
				}
				line := rules[i].RenderAppend(*chainPtr, prefixFrag)
				buf.WriteLine(line)
				appendRuleLines[i] = line
			}
			newRules = append(newRules, appendRuleLines...)
		}

		newHashes[chainName] = newChainHashes
		newChainToFullRules[chainName] = newRules

		return nil // Delay clearing the set until we've programmed ipfw.
	})
	// If rendering a delete by line number reached an unexpected state, error out so applyUpdates() can be retried.
	if deleteRenderingErr != nil {
		return deleteRenderingErr
	}

	// Do deletions at the end.  This ensures that we don't try to delete any chains that
	// are still referenced (because we'll have removed the references in the modify pass
	// above).  Note: if a chain is being deleted at the same time as a chain that it refers to
	// then we'll issue a create+flush instruction in the very first pass, which will sever the
	// references.
	t.dirtyChains.Iter(func(chainName string) error {
		if _, ok := t.desiredStateOfChain(chainName); !ok {
			// Chain deletion
			buf.WriteLine(fmt.Sprintf("ipfw delete %d", ChainNameToChainNum[chainName]))
			newHashes[chainName] = nil
		}
		return nil // Delay clearing the set until we've programmed ipfw.
	})

	buf.EndTransaction()

	if buf.Empty() {
		t.logCxt.Debug("Update ended up being no-op, skipping call to ip(6)tables-restore.")
	} else {
		// Get the contents of the buffer ready to send to ipfw-restore.  Warning: for perf, this is directly
		// accessing the buffer's internal array; don't touch the buffer after this point.
		t.opReporter.RecordOperation(fmt.Sprintf("update-%v-v%d", t.Name, t.IPVersion))

		if err := t.execIpfwRestore(buf); err != nil {
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
	t.dirtyAppend = set.New[string]()

	// Store off the updates.
	for chainName, hashes := range newHashes {
		if hashes == nil {
			delete(t.chainToDataplaneHashes, chainName)
		} else {
			t.chainToDataplaneHashes[chainName] = hashes
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

	if err := exec.Command(path).Run(); err != nil {
		return fmt.Errorf("exec Restore failed: %v", err)
	}
	return nil
}

// Chainへのルール追加
// ・chainToAppendedRulesの更新
func (t *RuleSet) InsertOrAppendRules(chainName string, rules []Rule) {
	t.logCxt.WithField("chainName", chainName).Debug("Updating rule insertions")
	// 古いルールの取得
	oldRules := t.chainToInsertedRules[chainName]
	// 新しいルールを保存
	t.chainToInsertedRules[chainName] = rules
	// ルール数の更新
	numRulesDelta := len(rules) - len(oldRules)
	t.gaugeNumRules.Add(float64(numRulesDelta))
	// 次回Apply時に反映するためのマーキング
	t.dirtyAppend.Add(chainName)

	// 参照数などの管理
	t.maybeIncrefReferredChains(chainName, rules)
	t.maybeDecrefReferredChains(chainName, oldRules)

	// 再チェックと更新を促すためのキャシュ無効化
	t.InvalidateDataplaneCache("insertion")
}

// Chainへのルール追加（Append版）
// 使うmapが違う
func (t *RuleSet) AppendRules(chainName string, rules []Rule) {
	t.logCxt.WithField("chainName", chainName).Debug("Updating rule appends")
	oldRules := t.chainToAppendedRules[chainName]
	t.chainToAppendedRules[chainName] = rules
	numRulesDelta := len(rules) - len(oldRules)
	t.gaugeNumRules.Add(float64(numRulesDelta))
	t.dirtyAppend.Add(chainName)

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
	// ChainNameToChainNumの登録
	ChainNameToChainNum[chain.Name] = chain.GetStartRuleNum()
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

func (t *RuleSet) maybeIncrefReferredChains(chainName string, rules []Rule) {
	if !t.chainIsReferenced(chainName) {
		return
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

func (t *RuleSet) desiredStateOfChain(chainName string) (chain *Chain, present bool) {
	if !t.chainIsReferenced(chainName) {
		return
	}
	chain, present = t.chainNameToChain[chainName]
	return
}

func (t *RuleSet) commentFrag(hash string) string {
	return fmt.Sprintf("// %s%s", t.hashCommentPrefix, hash)
}

func (r RuleSet) GetChainNum(name string) uint16 {
	return r.chainNameToChain[name].GetStartRuleNum()
}

func CalculateRuleHashes(chainName string, rules []Rule, features *environment.Features) []string {
	chain := Chain{
		Name: chainName,
		Rules: rules,
	}
	return (&chain).RuleHashes(features)
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
