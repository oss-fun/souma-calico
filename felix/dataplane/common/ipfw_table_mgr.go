package common

import (
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/ipfwtable"

)

type IpfwTableDataplane interface {
	AddOrReplaceTable(setMetadata ipfwtable.IpfwTableMetadata, members []string)
	AddMembers(setID string, newMembers []string)
	RemoveMembers(setID string, removedMembers []string)
	RemoveTable(setID string)
	GetIPFamily() ipfwtable.IPFamily
	GetTypeOf(setID string) (ipfwtable.IpfwTableType, error)
	GetDesiredMembers(setID string) (set.Set[string], error)
	QueueResync()
	ApplyUpdates()
	ApplyDeletions() (reschedule bool)
}

type IpfwTablesManager struct {
	dataplanes []IpfwTableDataplane
	maxSize    int
	lg         *log.Entry
}

func NewIPSetsManager(name string, ipsets_ IPSetsDataplane, maxIPSetSize int) *IPSetsManager {
	m := &IPSetsManager{
		maxSize: maxIPSetSize,
		lg:      log.WithField("name", name),
	}

	if ipsets_ != nil {
		m.dataplanes = append(m.dataplanes, ipsets_)
	}

	return m
}

