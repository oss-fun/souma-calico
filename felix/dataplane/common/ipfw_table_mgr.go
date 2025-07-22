package common

import (
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/ipfwtable"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

type IpfwTableDataplane interface {
	AddOrReplaceIpfwTable(setMetadata ipfwtable.IpfwTableMetadata, members []string)
	AddMembers(setID string, newMembers []string)
	RemoveMembers(setID string, removedMembers []string)
	RemoveIpfwTable(setID string)
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

func (m *IpfwTableManager) OnUpdate(msg interface{}) {
	switch msg := msg.(type) {
	// IP set-related messages, these are extremely common.
	case *proto.IpfwTableDeltaUpdate:
		m.lg.WithField("ipSetId", msg.Id).Debug("IP set delta update")
		for _, dp := range m.dataplanes {
			dp.AddMembers(msg.Id, msg.AddedMembers)
			dp.RemoveMembers(msg.Id, msg.RemovedMembers)
		}
	case *proto.IpfwTableUpdate:
		m.lg.WithField("ipSetId", msg.Id).Debug("IP set update")
		var setType ipfwtable.IpfwTableType
		switch msg.Type {
		case proto.IpfwTableUpdate_IP:
			setType = ipfwtable.IpfwTableTypeIP
		case proto.IpfwTableUpdate_NET:
			setType = ipfwtable.IpfwTableTypeNet
		default:
			m.lg.WithField("type", msg.Type).Panic("Unknown IP set type")
		}
		metadata := ipfwtable.IpfwTableMetadata{
			Type:    setType,
			SetID:   msg.Id,
			MaxSize: m.maxSize,
		}
		for _, dp := range m.dataplanes {
			dp.AddOrReplaceIpfwTable(metadata, msg.Members)
		}
	case *proto.IpfwTableRemove:
		m.lg.WithField("ipSetId", msg.Id).Debug("IP set remove")
		for _, dp := range m.dataplanes {
			dp.RemoveIpfwTable(msg.Id)
		}
	}
}

func (m *IpfwTableManager) CompleteDeferredWork() error {
	return nil
}
