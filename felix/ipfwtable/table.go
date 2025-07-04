//go:build freebsd

package ipfwtable

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	cprometheus "github.com/projectcalico/calico/libcalico-go/lib/prometheus"

	"github.com/projectcalico/calico/felix/deltatracker"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var (
	gaugeVecNumCalicoIpfwTable = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "felix_ipfw_table_calico",
		Help: "Number of active Calico Ipfw table.",
	}, []string{"ip_version"})
	gaugeNumTotalIpfwTable = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "felix_ipfw_table_total",
		Help: "Total number of active Ipfw table.",
	})
	countNumIpfwTableCalls = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_ipfw_table_calls",
		Help: "Number of ipfw table commands executed.",
	})
	countNumIpfwTableErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_ipfw_table_errors",
		Help: "Number of ipfw table command failures.",
	})
	countNumIpfwTableLinesExecuted = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_ipfw_table_lines_executed",
		Help: "Number of ipfw table operations executed.",
	})
	summaryExecStart = cprometheus.NewSummary(prometheus.SummaryOpts{
		Name: "felix_exec_time_micros",
		Help: "Summary of time taken to fork/exec child processes",
	})
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
