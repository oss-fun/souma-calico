package ipfwtable

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/deltatracker"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
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
	nextTempIPSetIdx       uint
	ipfwTableWithDirtyMembers set.Set[string]

	resyncRequired bool

	newCmd cmdFactory

	sleep func(time.Duration)

	gaugeNumIpsets prometheus.Gauge

	logCxt *log.Entry

	opReporter logutils.OpRecorder

	neededIpfwTableNames set.Set[string]
}

func NewIPSets(ipVersionConfig *IPVersionConfig, recorder logutils.OpRecorder) *IPSets {
	return NewIPSetsWithShims(
		ipVersionConfig,
		recorder,
		newRealCmd,
		time.Sleep,
	)
}

func NewIPSetsWithShims(
	ipVersionConfig *IPVersionConfig,
	recorder logutils.OpRecorder,
	cmdFactory cmdFactory,
	sleep func(time.Duration),
) *IPSets {
	familyStr := string(ipVersionConfig.Family)
	return &IPSets{
		IPVersionConfig: ipVersionConfig,

		setNameToAllMetadata: map[string]dataplaneMetadata{},
		setNameToProgrammedMetadata: deltatracker.New[string, dataplaneMetadata](
			deltatracker.WithValuesEqualFn[string, dataplaneMetadata](func(a, b dataplaneMetadata) bool {
				return a == b
			}),
			deltatracker.WithLogCtx[string, dataplaneMetadata](log.WithFields(log.Fields{
				"ipsetFamily": ipVersionConfig.Family,
			})),
		),
		mainSetNameToMembers: map[string]*deltatracker.SetDeltaTracker[IPSetMember]{},

		ipSetsWithDirtyMembers: set.New[string](),
		resyncRequired:         true,

		newCmd: cmdFactory,
		sleep:  sleep,

		gaugeNumIpsets: gaugeVecNumCalicoIpsets.WithLabelValues(familyStr),

		logCxt: log.WithFields(log.Fields{
			"family": ipVersionConfig.Family,
		}),
		opReporter: recorder,
	}
}
