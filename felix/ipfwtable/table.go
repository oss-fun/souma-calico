//go:build freebsd

package ipfwtable

import (
	"os"
	"os/exec"
	"bufio"
	"bytes"
	"fmt"
	"time"
	"io"
	"strings"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/deltatracker"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

const (
	MaxIpfwTableDeletionsPerIteration = 1
	RESTORE_FILE = "/tmp/ipfw_table_restore.sh"
)

type dataplaneMetadata struct {
	Type         IpfwTableType
	MaxSize      int
	RangeMin     int
	RangeMax     int
	DeleteFailed bool
}

type IpfwTable struct {
	IPVersionConfig *IPVersionConfig

	setNameToAllMetadata map[string]dataplaneMetadata
	setNameToProgrammedMetadata *deltatracker.DeltaTracker[string, dataplaneMetadata]

	mainSetNameToMembers   map[string]*deltatracker.SetDeltaTracker[IpfwTableMember]
	nextTempIpfwTableIdx       uint
	ipfwTableWithDirtyMembers set.Set[string]

	resyncRequired bool

	newCmd cmdFactory

	sleep func(time.Duration)

	gaugeNumIpfwTable prometheus.Gauge

	logCxt *log.Entry
	
	restoreInCopy bytes.Buffer
	stdoutCopy bytes.Buffer
	stderrCopy bytes.Buffer


	opReporter logutils.OpRecorder

	neededIpfwTableNames set.Set[string]
}

func NewIpfwTable(ipVersionConfig *IPVersionConfig, recorder logutils.OpRecorder) *IpfwTable {
	return NewIpfwTableWithShims(
		ipVersionConfig,
		recorder,
		newRealCmd,
		time.Sleep,
	)
}

func NewIpfwTableWithShims(
	ipVersionConfig *IPVersionConfig,
	recorder logutils.OpRecorder,
	cmdFactory cmdFactory,
	sleep func(time.Duration),
) *IpfwTable {
	familyStr := string(ipVersionConfig.Family)
	return &IpfwTable{
		IPVersionConfig: ipVersionConfig,

		setNameToAllMetadata: map[string]dataplaneMetadata{},
		setNameToProgrammedMetadata: deltatracker.New[string, dataplaneMetadata](
			deltatracker.WithValuesEqualFn[string, dataplaneMetadata](func(a, b dataplaneMetadata) bool {
				return a == b
			}),
			deltatracker.WithLogCtx[string, dataplaneMetadata](log.WithFields(log.Fields{
				"ipfwTableFamily": ipVersionConfig.Family,
			})),
		),
		mainSetNameToMembers: map[string]*deltatracker.SetDeltaTracker[IpfwTableMember]{},

		ipfwTableWithDirtyMembers: set.New[string](),
		resyncRequired:         true,

		newCmd: cmdFactory,
		sleep:  sleep,

		gaugeNumIpfwTable: gaugeVecNumCalicoIpfwTable.WithLabelValues(familyStr),

		logCxt: log.WithFields(log.Fields{
			"family": ipVersionConfig.Family,
		}),
		opReporter: recorder,
	}
}

func (s *IpfwTable) AddOrReplaceIpfwTable(setMetadata IpfwTableMetadata, members []string) {
	setID := setMetadata.SetID

	// Mark that we want this IP set to exist and with the correct size etc.
	// If the IP set exists, but it has the wrong metadata then the
	// DeltaTracker will catch that and mark it for recreation.
	mainIpfwTableName := s.IPVersionConfig.NameForMainIpfwTable(setID)
	dpMeta := dataplaneMetadata{
		Type:     setMetadata.Type,
		MaxSize:  setMetadata.MaxSize,
		RangeMin: setMetadata.RangeMin,
		RangeMax: setMetadata.RangeMax,
	}
	s.setNameToAllMetadata[mainIpfwTableName] = dpMeta
	if s.ipfwtableNeeded(mainIpfwTableName) {
		s.logCxt.WithFields(log.Fields{
			"setID":   setID,
			"setType": setMetadata.Type,
		}).Info("Queueing IP set for creation")
		s.setNameToProgrammedMetadata.Desired().Set(mainIpfwTableName, dpMeta)
	} else if log.IsLevelEnabled(log.DebugLevel) {
		s.logCxt.WithFields(log.Fields{
			"setID":   setID,
			"setType": setMetadata.Type,
		}).Debug("IP set is filtered out, skipping creation.")
	}

	// Set the desired contents of the IP set.
	canonMembers := s.filterAndCanonicaliseMembers(setMetadata.Type, members)
	memberTracker := s.getOrCreateMemberTracker(mainIpfwTableName)

	desiredMembers := memberTracker.Desired()
	desiredMembers.Iter(func(k IpfwTableMember) {
		if canonMembers.Contains(k) {
			canonMembers.Discard(k)
		} else {
			desiredMembers.Delete(k)
		}
	})
	canonMembers.Iter(func(m IpfwTableMember) error {
		desiredMembers.Add(m)
		return nil
	})
	s.updateDirtiness(mainIpfwTableName)
}

func (s *IpfwTable) RemoveIpfwTable(setID string) {
	setName := s.nameForMainIpfwTable(setID)
	delete(s.setNameToAllMetadata, setName)
	s.setNameToProgrammedMetadata.Desired().Delete(setName)
	if _, ok := s.setNameToProgrammedMetadata.Dataplane().Get(setName); ok {
		s.logCxt.WithField("setID", setID).Info("Queueing IP set for removal")
		s.mainSetNameToMembers[setName].Desired().DeleteAll()
	} else {
		log.Debug("IP set to remove not in the dataplane.")
		delete(s.mainSetNameToMembers, setName)
	}
	s.updateDirtiness(setName)
}

func (s *IpfwTable) nameForMainIpfwTable(setID string) string {
	return s.IPVersionConfig.NameForMainIpfwTable(setID)
}

func (s *IpfwTable) AddMembers(setID string, newMembers []string) {
	setName := s.nameForMainIpfwTable(setID)
	setMeta, ok := s.setNameToAllMetadata[setName]
	if !ok {
		log.WithField("setName", setName).Panic("AddMembers called for nonexistent IP set.")
	}
	canonMembers := s.filterAndCanonicaliseMembers(setMeta.Type, newMembers)
	if canonMembers.Len() == 0 {
		s.logCxt.Debug("After filtering, found no members to add")
		return
	}
	membersTracker := s.mainSetNameToMembers[setName]
	canonMembers.Iter(func(member IpfwTableMember) error {
		membersTracker.Desired().Add(member)
		return nil
	})
	s.updateDirtiness(setName)
}

func (s *IpfwTable) getOrCreateMemberTracker(mainIpfwTableName string) *deltatracker.SetDeltaTracker[IpfwTableMember] {
	dt := s.mainSetNameToMembers[mainIpfwTableName]
	if dt == nil {
		dt = deltatracker.NewSetDeltaTracker[IpfwTableMember]()
		s.mainSetNameToMembers[mainIpfwTableName] = dt
	}
	return dt
}

func (s *IpfwTable) RemoveMembers(setID string, removedMembers []string) {
	setName := s.nameForMainIpfwTable(setID)
	setMeta, ok := s.setNameToAllMetadata[setName]
	if !ok {
		log.WithField("setName", setName).Panic("RemoveMembers called for nonexistent IP set.")
	}
	canonMembers := s.filterAndCanonicaliseMembers(setMeta.Type, removedMembers)
	if canonMembers.Len() == 0 {
		s.logCxt.Debug("After filtering, found no members to remove")
		return
	}
	membersTracker := s.mainSetNameToMembers[setName]
	canonMembers.Iter(func(member IpfwTableMember) error {
		membersTracker.Desired().Delete(member)
		return nil
	})
	s.updateDirtiness(setName)
}

func (s *IpfwTable) QueueResync() {
}

func (s *IpfwTable) GetIPFamily() IPFamily {
	return s.IPVersionConfig.Family
}

func (s *IpfwTable) GetTypeOf(setID string) (IpfwTableType, error) {
	setName := s.nameForMainIpfwTable(setID)
	setMeta, ok := s.setNameToAllMetadata[setName]
	if !ok {
		return "", fmt.Errorf("ipset %s not found", setID)
	}
	return setMeta.Type, nil
}

func (s *IpfwTable) filterAndCanonicaliseMembers(ipfwTableType IpfwTableType, members []string) set.Set[IpfwTableMember] {
	filtered := set.New[IpfwTableMember]()
	for _, member := range members {
		filtered.Add(ipfwTableType.CanonicaliseMember(member))
	}
	return filtered
}

func (s *IpfwTable) GetDesiredMembers(setID string) (set.Set[string], error) {
	setName := s.nameForMainIpfwTable(setID)

	_, ok := s.setNameToAllMetadata[setName]
	if !ok {
		return nil, fmt.Errorf("ipset %s not found", setID)
	}

	memberTracker, ok := s.mainSetNameToMembers[setName]
	if !ok {
		return nil, fmt.Errorf("ipset %s not found in members tracker", setID)
	}
	strs := set.New[string]()
	memberTracker.Desired().Iter(func(k IpfwTableMember) {
		strs.Add(k.String())
	})
	return strs, nil
}

func (s *IpfwTable) ApplyUpdates() {
	success := false
	retryDelay := 1 * time.Millisecond
	backOff := func() {
		s.sleep(retryDelay)
		retryDelay *= 2
	}

	for attempt := 0; attempt < 10; attempt++ {
		if attempt > 0 {
			s.logCxt.Info("Retrying after an ipsets update failure...")
		}
		if s.resyncRequired {
			s.logCxt.Debug("Resyncing ipsets with dataplane.")
			s.opReporter.RecordOperation(fmt.Sprint("resync-ipfwtable-v", s.IPVersionConfig.Family.Version()))

			if err := s.tryResync(); err != nil {
				s.logCxt.WithError(err).Warning("Failed to resync with dataplane")
				backOff()
				continue
			}
			s.resyncRequired = false
		}

		s.tryTempIpfwTableDeletions()

		if err := s.tryUpdates(); err != nil {
			s.logCxt.WithError(err).Warning("Failed to update IP sets. Marking dataplane for resync.")
			s.resyncRequired = true
			countNumIpfwTableErrors.Inc()
			backOff()
			continue
		}

		success = true
		break
	}
	if !success {
		s.dumpIpfwTableToLog()
		s.logCxt.Panic("Failed to update IP sets after multiple retries.")
	}
	gaugeNumTotalIpfwTable.Set(float64(s.setNameToProgrammedMetadata.Dataplane().Len()))
}

func (s *IpfwTable) tryResync() (err error) {
	// Log the time spent as we exit the function.
	resyncStart := time.Now()
	defer func() {
		s.logCxt.WithFields(log.Fields{
			"resyncDuration":           time.Since(resyncStart),
			"ipSetsWithDirtyMembers":   s.ipfwTableWithDirtyMembers.Len(),
			"ipSetsToCreateOrRecreate": s.setNameToProgrammedMetadata.PendingUpdates().Len(),
			"ipSetsToDelete":           s.setNameToProgrammedMetadata.PendingDeletions().Len(),
		}).Debug("Finished IPSets resync")
	}()

	// Figure out if debug logging is enabled so we can disable some expensive-to-calculate logs
	// in the tight loop below if they're not going to be emitted.  This speeds up the loop
	// by a factor of 3-4x!
	debug := log.GetLevel() >= log.DebugLevel

	// Clear the dataplane metadata view, we'll build it back up again as we
	// scan.
	s.setNameToProgrammedMetadata.Dataplane().DeleteAll()

	ipfwTable, err := s.CalicoIpfwTable()
	if err != nil {
		s.logCxt.WithError(err).Error("Failed to get the list of ipsets")
		return
	}
	if debug {
		s.logCxt.Debugf("List of ipsets: %v", ipfwTable)
	}

	for _, name := range ipfwTable {
		if debug {
			s.logCxt.Debugf("Parsing IP set %v.", name)
		}
		err = s.resyncIpfwTable(name)
		if err != nil {
			s.logCxt.WithError(err).Errorf("Failed to parse ipset %v", name)
			return
		}
	}

	// Mark any IP sets that we didn't see as empty.
	for name, members := range s.mainSetNameToMembers {
		if _, ok := s.setNameToProgrammedMetadata.Dataplane().Get(name); ok {
			// In the dataplane, we should have updated its members above.
			continue
		}
		if _, ok := s.setNameToAllMetadata[name]; !ok {
			// Defensive: this IP set is not in the dataplane, and it's not
			// one we are tracking, clean up its member tracker.
			log.WithField("name", name).Warn(
				"Cleaning up leaked(?) IP set member tracker.")
			delete(s.mainSetNameToMembers, name)
			continue
		}
		// We're tracking this IP set, but we didn't find it in the dataplane;
		// reset the members set to empty.
		members.Dataplane().DeleteAll()
	}

	return
}

func (s *IpfwTable) CalicoIpfwTable() ([]string, error) {
	var ipfwTable []string
	err := s.runIpfwTableList("all", func(scanner *bufio.Scanner) error {
		debug := log.GetLevel() >= log.DebugLevel
		for scanner.Scan() {
			name := scanner.Text()
			// Look up to see if this is one of our IP sets.
			if !s.IPVersionConfig.OwnsIpfwTable(name) {
				if debug {
					s.logCxt.WithField("name", name).Debug("Skip non-Calico/wrong version IP set.")
				}
				continue
			}
			ipfwTable = append(ipfwTable, name)
		}
		return scanner.Err()
	})
	if err != nil {
		return nil, err
	}
	return ipfwTable, nil
}

func (s *IpfwTable) resyncIpfwTable(ipfwTableName string) error {
	if ipfwTableName == "" {
		return fmt.Errorf("no ipset name specified")
	}
	
	err := s.runIpfwTableList(ipfwTableName, func(scanner *bufio.Scanner) error {
		debug := log.GetLevel() >= log.DebugLevel
		ipfwTableName := ""
		var ipfwTableType IpfwTableType
		for scanner.Scan() {
			line := scanner.Text()
			if debug {
				s.logCxt.Debugf("Parsing line: %q", line)
			}
			if strings.HasPrefix(line, "Name:") {
				ipfwTableName = strings.Split(line, " ")[1]
				if debug {
					s.logCxt.WithField("setName", ipfwTableName).Debug("Parsing IP set.")
				}
			}
			if strings.HasPrefix(line, "Type:") {
				ipfwTableType = IpfwTableType(strings.Split(line, " ")[1])
				if debug {
					s.logCxt.WithField("type", ipfwTableType).Debug("Parsed type of IP set.")
				}
			}
			if strings.HasPrefix(line, "Header:") {
				// When we hit the Header line we should know the name, and type of the IP set, which lets
				// us update the tracker.
				parts := strings.Split(line, " ")
				meta := dataplaneMetadata{
					Type: ipfwTableType,
				}
				for idx, p := range parts {
					if p == "maxelem" {
						if idx+1 >= len(parts) {
							return fmt.Errorf(
								"failed to parse ipset list Header line, nothing after 'maxelem'. line: '%v'", line)
						}
						maxElem, err := strconv.Atoi(parts[idx+1])
						if err != nil {
							return fmt.Errorf(
								"Failed to parse ipset list Header line. line: '%v', err: %w", line, err)
						}
						meta.MaxSize = maxElem
						break
					}
					if p == "range" {
						if idx+1 >= len(parts) {
							return fmt.Errorf(
								"Failed to parse ipset list Header line, nothing after 'range'. line: '%v'", line)
						}
						// For bitmaps, we see "range 123-456"
						rMin, rMAx, err := ParseRange(parts[idx+1])
						if err != nil {
							return fmt.Errorf(
								"Failed to parse ipset list Header line. line: '%v', err: %w", line, err)
						}
						meta.RangeMin = rMin
						meta.RangeMax = rMAx
						break
					}
				}
				s.setNameToProgrammedMetadata.Dataplane().Set(ipfwTableName, meta)
			}
			if strings.HasPrefix(line, "Members:") {
				// Start of a Members entry, following this, there'll be one member per
				// line then EOF or a blank line.

				// Look up to see if this is one of our IP sets.
				if !s.IPVersionConfig.OwnsIpfwTable(ipfwTableName) || s.IPVersionConfig.IsTempIpfwTableName(ipfwTableName) {
					if debug {
						s.logCxt.WithField("name", ipfwTableName).Debug("Skip parsing members of IP set.")
					}
					return nil
				}

				if !ipfwTableType.IsValid() {
					s.logCxt.WithFields(log.Fields{
						"setName": ipfwTableName,
						"type":    string(ipfwTableType),
					}).Warning("Dataplane IP set has unknown type.")
				}

				// One of our IP sets; we need to parse its members.
				logCxt := s.logCxt.WithField("setName", ipfwTableName)
				memberTracker := s.getOrCreateMemberTracker(ipfwTableName)
				numExtrasExpected := memberTracker.PendingDeletions().Len()
				err := memberTracker.Dataplane().ReplaceFromIter(func(f func(k IpfwTableMember)) error {
					for scanner.Scan() {
						line := scanner.Text()
						if line == "" {
							// End of members
							break
						}
						var canonMember IpfwTableMember
						if ipfwTableType.IsValid() {
							canonMember = ipfwTableType.CanonicaliseMember(line)
						} else {
							// Unknown type found in dataplane, record it as
							// a raw string.  Then we'll clean up the IP set
							// when we go to sync.
							canonMember = rawIpfwTableMember(line)
						}
						if debug {
							logCxt.WithFields(log.Fields{
								"member": line,
								"canon":  canonMember,
							}).Debug("Found member in dataplane")
						}
						f(canonMember)
					}
					return scanner.Err()
				})
				if err != nil {
					return fmt.Errorf("Failed to read members from 'ipset list'. err: %w", err)
				}

				if numMissing := memberTracker.PendingUpdates().Len(); numMissing > 0 {
					logCxt.WithField("numMissing", numMissing).Info(
						"Resync found members missing from dataplane.")
				}
				if numExtras := memberTracker.PendingDeletions().Len() - numExtrasExpected; numExtras > 0 {
					logCxt.WithField("numExtras", numExtras).Info(
						"Resync found extra members in dataplane.")
				}

				s.updateDirtiness(ipfwTableName)
			}
		}
		return scanner.Err()
	})
	if err != nil {
		return err
	}
	return nil
}

func (s *IpfwTable) tryTempIpfwTableDeletions() {
	numDeletions := 0
	s.setNameToProgrammedMetadata.PendingDeletions().Iter(func(setName string) deltatracker.IterAction {
		if numDeletions >= MaxIpfwTableDeletionsPerIteration {
			// Deleting IP sets is slow (40ms) and serialised in the kernel.  Avoid holding up the main loop
			// for too long.  We'll leave the remaining sets pending deletion and mop them up next time.
			log.Debugf("Deleted batch of 20 temp IP sets, rate limiting further IP set deletions.")
			// Leave the item in the set, so we'll do another batch of deletions next time around the loop.
			return deltatracker.IterActionNoOpStopIteration
		}
		if !s.IPVersionConfig.IsTempIpfwTableName(setName) {
			return deltatracker.IterActionNoOp
		}
		meta, _ := s.setNameToProgrammedMetadata.Dataplane().Get(setName)
		if meta.DeleteFailed {
			return deltatracker.IterActionNoOp
		}
		logCxt := s.logCxt.WithField("setName", setName)
		logCxt.Info("Deleting IP set.")
		if err := s.deleteIpfwTable(setName); err != nil {
			logCxt.WithError(err).Warning("Failed to delete temp IP set. Will retry...")
			return deltatracker.IterActionNoOp
		}
		numDeletions++
		return deltatracker.IterActionUpdateDataplane
	})
}

func (s *IpfwTable) runIpfwTableList(arg string, parsingFunc func(*bufio.Scanner) error) error {
	cmd := s.newCmd("ipfw", "table", arg, "list")
	cmdStr := fmt.Sprintf("ipfw table %v list", arg)
	// Grab stdout as a pipe so we can stream through the (potentially very large) output.
	out, err := cmd.StdoutPipe()
	if err != nil {
		s.logCxt.WithError(err).Errorf("Failed to get pipe for '%v'.", cmdStr)
		return err
	}
	// Capture error output into a buffer.
	var stderr bytes.Buffer
	cmd.SetStderr(&stderr)
	execStartTime := time.Now()
	err = cmd.Start()
	if err != nil {
		s.logCxt.WithError(err).Errorf("Failed to start '%v'.", cmdStr)
		return err
	}
	summaryExecStart.Observe(float64(time.Since(execStartTime).Nanoseconds()) / 1000.0)

	// Use a scanner to chunk the input into lines.
	scanner := bufio.NewScanner(out)
	parsingErr := parsingFunc(scanner)
	if parsingErr == nil {
		// In case the parsingFunc stopped early, drain stdout fully.
		for scanner.Scan() {
		}
		parsingErr = scanner.Err()
	}
	closeErr := out.Close()
	err = cmd.Wait()
	logCxt := s.logCxt.WithField("stderr", stderr.String())
	if scanner.Err() != nil {
		err = scanner.Err()
		logCxt.WithError(err).Errorf("Failed to read '%v' output.", cmdStr)
		return err
	}
	if err != nil {
		logCxt.WithError(err).Errorf("Bad return code from '%v'.", cmdStr)
		return err
	}
	if closeErr != nil {
		logCxt.WithError(closeErr).Errorf("Failed to close stdout from '%v'.", cmdStr)
		return closeErr
	}
	if parsingErr != nil {
		logCxt.WithError(parsingErr).Errorf("Failed to process '%v' output.", cmdStr)
		return parsingErr
	}
	return nil
}

func ParseRange(s string) (min int, max int, err error) {
	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		err = fmt.Errorf("failed to parse range %q", s)
		return
	}
	if min, err = strconv.Atoi(parts[0]); err != nil {
		err = fmt.Errorf("failed to parse range %q (%w)", s, err)
		return
	}
	if max, err = strconv.Atoi(parts[1]); err != nil {
		err = fmt.Errorf("failed to parse range %q (%w)", s, err)
		return
	}
	return
}

func (s *IpfwTable) tryUpdates() error {
	var dirtyIpfwTable []string
	s.ipfwTableWithDirtyMembers.Iter(func(setName string) error {
		if _, ok := s.setNameToProgrammedMetadata.Desired().Get(setName); !ok {
			return nil
		}
		dirtyIpfwTable = append(dirtyIpfwTable, setName)
		return nil
	})
	s.setNameToProgrammedMetadata.PendingUpdates().Iter(func(setName string, v dataplaneMetadata) deltatracker.IterAction {
		if !s.ipfwTableWithDirtyMembers.Contains(setName) {
			dirtyIpfwTable = append(dirtyIpfwTable, setName)
		}
		return deltatracker.IterActionNoOp
	})
	if len(dirtyIpfwTable) == 0 {
		s.logCxt.Debug("No dirty IP sets.")
		return nil
	}
	s.opReporter.RecordOperation(fmt.Sprint("update-ipfw-table-", s.IPVersionConfig.Family.Version()))

	countNumIpfwTableCalls.Inc()
	file, err := os.OpenFile(RESTORE_FILE, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
 		s.logCxt.WithError(err).Error("Failed to open file for writing ipfw restore input.")  
		return err
	}

	_, shErr := file.Write([]byte("#!/bin/sh\n"))

	stdin := io.MultiWriter(&s.restoreInCopy, file)
	
	var writeErr error
	for _, setName := range dirtyIpfwTable {
		if log.IsLevelEnabled(log.DebugLevel) {
			log.WithField("setName", setName).Debug("Writing updates to IP set.")
		}
		writeErr = s.writeUpdates(setName, stdin)
		if writeErr != nil {
			break
		}
	}

	file.Close()
	cmdErr := exec.Command(RESTORE_FILE).Run()

	if err = firstNonNilErr(shErr, writeErr, cmdErr); err != nil {
		s.logCxt.WithFields(log.Fields{
			"shErr":      shErr,
			"writeErr":   writeErr,
			"cmdErr":     cmdErr,
			"input":      s.restoreInCopy.String(),
		}).Warning("Failed to complete ipfw restore, IP sets may be out-of-sync.")
		return fmt.Errorf("failed to write one or more Ipfw: %v", err)
	}

	s.ipfwTableWithDirtyMembers.Clear()

	return nil
}

func (s *IpfwTable) writeUpdates(setName string, w io.Writer) (err error) {
	logCxt := s.logCxt.WithField("setName", setName)

	desiredMeta, desiredExists := s.setNameToProgrammedMetadata.Desired().Get(setName)
	dpMeta, dpExists := s.setNameToProgrammedMetadata.Dataplane().Get(setName)

	members, membersExists := s.mainSetNameToMembers[setName]

	if !desiredExists {
		log.WithField("setName", setName).Panic("writeUpdates called for pending deletion?")
	}
	if !membersExists {
		log.WithField("setName", setName).Panic("writeUpdates called for missing IP set?")
	}

	// If the metadata needs to change then we have to write to a temporary IP
	// set and swap it into place.
	needTempIpfwTable := dpExists && dpMeta != desiredMeta
	if needTempIpfwTable {
		log.WithFields(log.Fields{
			"desired":   desiredMeta,
			"dataplane": dpMeta,
			"setName":   setName,
		}).Info("IP set metadata change, need to use a temporary IP set.")
	}
	// If the IP set doesn't exist yet, we need to create it.
	needCreate := !dpExists

	// writeLine until an error occurs, writeLine writes a line to the output, after an error,
	// it is a no-op.
	writeLine := func(format string, a ...interface{}) {
		if err != nil {
			return
		}
		line := fmt.Sprintf(format, a...) + "\n"
		logCxt.WithField("line", line).Debug("Writing line to ipset restore")
		lineBytes := []byte(line)
		_, err = w.Write(lineBytes)
		if err != nil {
			logCxt.WithError(err).WithFields(log.Fields{
				"line": lineBytes,
			}).Error("Failed to write to ipset restore")
			return
		}
		countNumIpfwTableLinesExecuted.Inc()
	}

	var targetSet, tempSet string
	if needTempIpfwTable {
		tempSet = s.nextFreeTempIpfwTableName()
		targetSet = tempSet
		// Temp IP set is empty.
		members.Dataplane().DeleteAll()
	} else {
		targetSet = setName
	}
	if needCreate || needTempIpfwTable {
		logCxt.WithField("ipSetToCreate", targetSet).Debug("Creating IP set")
		if desiredMeta.Type == "net" || desiredMeta.Type == "ip" {
			desiredMeta.Type = "addr"
		}
		writeLine("ipfw table %s create type %s", targetSet, desiredMeta.Type)

	}
	if err != nil {
		return
	}
	members.PendingDeletions().Iter(func(member IpfwTableMember) deltatracker.IterAction {
		writeLine("ipfw table %s delete %s", targetSet, member)
		if err != nil {
			// Note, just exiting early here to save a load of no-ops.
			// If we exit with an error, the dataplane state will be resynced.
			return deltatracker.IterActionNoOpStopIteration
		}
		return deltatracker.IterActionUpdateDataplane
	})
	members.PendingUpdates().Iter(func(member IpfwTableMember) deltatracker.IterAction {
		memberStr := member.String()
		writeLine("ipfw table %s add %s", targetSet, memberStr)
		if err != nil {
			// Note, just exiting early here to save a load of no-ops.
			// If we exit with an error, the dataplane state will be resynced.
			return deltatracker.IterActionNoOpStopIteration
		}
		return deltatracker.IterActionUpdateDataplane
	})
	if err != nil {
		return
	}

	if needCreate || needTempIpfwTable {
		if needTempIpfwTable {
			// After the swap, the temp IP set has the _old_ dataplane metadata.
			s.setNameToProgrammedMetadata.Dataplane().Set(tempSet, dpMeta)
		}
		// The main IP set now has the correct metadata.
		s.setNameToProgrammedMetadata.Dataplane().Set(setName, desiredMeta)
	}
	return
}

func (s *IpfwTable) nextFreeTempIpfwTableName() string {
	for {
		candidateName := s.IPVersionConfig.NameForTempIpfwTable(s.nextTempIpfwTableIdx)
		s.nextTempIpfwTableIdx++
		if _, ok := s.setNameToProgrammedMetadata.Dataplane().Get(candidateName); ok {
			log.WithField("candidate", candidateName).Warning(
				"Skipping in-use temporary IP set name (previous cleanup failure?)")
			continue
		}
		return candidateName
	}
}

func (s *IpfwTable) ApplyDeletions() bool {
	numDeletions := 0
	s.setNameToProgrammedMetadata.PendingDeletions().Iter(func(setName string) deltatracker.IterAction {
		if numDeletions >= MaxIpfwTableDeletionsPerIteration {
			log.Debugf("Deleted batch of %d IP sets, rate limiting further IP set deletions.", MaxIpfwTableDeletionsPerIteration)
			return deltatracker.IterActionNoOpStopIteration
		}
		meta, _ := s.setNameToProgrammedMetadata.Dataplane().Get(setName)
		if meta.DeleteFailed {
			return deltatracker.IterActionNoOp
		}
		logCxt := s.logCxt.WithField("setName", setName)
		logCxt.Info("Deleting IP set.")
		if err := s.deleteIpfwTable(setName); err != nil {
			logCxt.WithError(err).Warning("Failed to delete IP set. Will retry on next resync.")
			meta.DeleteFailed = true
			s.setNameToProgrammedMetadata.Dataplane().Set(setName, meta)
			return deltatracker.IterActionNoOp
		}
		numDeletions++
		if _, ok := s.setNameToAllMetadata[setName]; !ok {
			logCxt.Debug("IP set now gone from dataplane, removing from members tracker.")
			delete(s.mainSetNameToMembers, setName)
		} else {
			logCxt.Debug("IP set now gone from dataplane but still " +
				"tracking its members (it is filtered out).")
			s.mainSetNameToMembers[setName].Dataplane().DeleteAll()
		}
		return deltatracker.IterActionUpdateDataplane
	})
	numDeletionsPending := s.setNameToProgrammedMetadata.Dataplane().Len()
	s.gaugeNumIpfwTable.Set(float64(numDeletionsPending))
	if numDeletions == 0 {
		return false
	}
	return numDeletionsPending > 0
}

func (s *IpfwTable) deleteIpfwTable(tableName string) error {
	s.logCxt.WithField("setName", tableName).Info("Deleting IP set.")
	cmd := s.newCmd("ipfw", "table", string(tableName), "destroy")
	if output, err := cmd.CombinedOutput(); err != nil {
		s.logCxt.WithError(err).WithFields(log.Fields{
			"setName": tableName,
			"output":  string(output),
		}).Warn("Failed to delete IP set, may be out-of-sync.")
		return err
	}
	s.logCxt.WithField("setName", tableName).Info("Deleted IP set")
	return nil
}

func (s *IpfwTable) dumpIpfwTableToLog() {
	ipfwTable, err := s.CalicoIpfwTable()
	if err != nil {
		s.logCxt.WithError(err).Error("Failed to get the list of IP sets.")
		return
	}
	s.logCxt.Infof("Current state of IP sets: %v", strings.Join(ipfwTable, " "))

	for _, name := range ipfwTable {
		s.logCxt.Infof("Dumping IP set %v.", name)

		err := s.runIpfwTableList(name, func(scanner *bufio.Scanner) error {
			for scanner.Scan() {
				s.logCxt.Infof("%v", scanner.Text())
			}
			return scanner.Err()
		})
		if err != nil {
			s.logCxt.WithError(err).Errorf("Failed to read ipset %v", name)
			continue
		}
	}
}

func firstNonNilErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *IpfwTable) updateDirtiness(name string) {
	memberTracker, ok := s.mainSetNameToMembers[name]
	if !ok {
		s.ipfwTableWithDirtyMembers.Discard(name)
		return
	}
	if !s.ipfwtableNeeded(name) {
		// If the IP set is filtered out we don't program its members.
		s.ipfwTableWithDirtyMembers.Discard(name)
		return
	}
	if memberTracker.InSync() {
		s.ipfwTableWithDirtyMembers.Discard(name)
	} else {
		s.ipfwTableWithDirtyMembers.Add(name)
	}
}

func (s *IpfwTable) ipfwtableNeeded(name string) bool {
	if s.neededIpfwTableNames == nil {
		// We're not filtering down to a "needed" set, so all IP sets are needed.
		return true
	}

	// We are filtering down, so compare against the needed set.
	return s.neededIpfwTableNames.Contains(name)
}
