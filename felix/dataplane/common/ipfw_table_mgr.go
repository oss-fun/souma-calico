package common

import (
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/ipfwtable"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
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

type IpfwTableManager struct {
	dataplanes []IpfwTableDataplane
	maxSize    int
	lg         *log.Entry
}

func NewIpfwTableManager(name string, ipfwtable_ IpfwTableDataplane, maxIpfwTableSize int) *IpfwTableManager {
	m := &IpfwTableManager{
		maxSize: maxIpfwTableSize,
		lg:      log.WithField("name", name),
	}

	if ipfwtable_ != nil {
		m.dataplanes = append(m.dataplanes, ipfwtable_)
	}

	return m
}

