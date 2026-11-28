//go:build freebsd

package ipfw

import (
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/projectcalico/calico/felix/proto"
)

type MatchCriteria []string

func Match() MatchCriteria {
	return nil
}

func (m MatchCriteria) Render() string {
	return strings.Join([]string(m), " ")
}

func (m MatchCriteria) String() string {
	return m.Render()
}

func (m MatchCriteria) Tagged(tag uint16) MatchCriteria {
	return append(m, fmt.Sprintf("tagged %d", tag))
}

func (m MatchCriteria) NotTagged(tag uint16) MatchCriteria {
	return append(m, fmt.Sprintf("not tagged %d", tag))
}

// IPFW の tag はビットではなく番号なので、複数の tag を OR でまとめてはいけない
// （例: Accept=1, Pass=2 の OR は 3 になり、別の tag の番号になる）。
// 複数の tag は、ipfw の tag-list（"tagged 1,2"）で指定する。
// ipfw(8): "tagged tag-list: Matches packets whose tags are included in tag-list"

// TaggedAnyOf は、tags のどれか1つでも付いていれば一致する（OR）。
// 本家 iptables の MarkNotClear(A | B) に相当する。
func (m MatchCriteria) TaggedAnyOf(tags ...uint16) MatchCriteria {
	return append(m, fmt.Sprintf("tagged %s", tagList(tags)))
}

// NotTaggedAnyOf は、tags がどれも付いていなければ一致する（すべて「なし」の AND）。
// 本家 iptables の MarkClear(A | B) に相当する。
func (m MatchCriteria) NotTaggedAnyOf(tags ...uint16) MatchCriteria {
	return append(m, fmt.Sprintf("not tagged %s", tagList(tags)))
}

func tagList(tags []uint16) string {
	if len(tags) == 0 {
		log.Fatalf("tagList: no tags given")
	}
	parts := make([]string, len(tags))
	for i, t := range tags {
		parts[i] = fmt.Sprintf("%d", t)
	}
	return strings.Join(parts, ",")
}

func (m MatchCriteria) Protocol(p interface{}) MatchCriteria {
	switch proto := p.(type) {
	case int:
		return append(m, fmt.Sprintf("proto %d", proto))
	case string:
		return append(m, fmt.Sprintf("proto %s", proto))
	default:
		log.Fatalf("Protocol failed: required int or string: %T", p)
		return nil
	}
}

func (m MatchCriteria) NotProtocol(p interface{}) MatchCriteria {
	switch proto := p.(type) {
	case uint8:
		return append(m, fmt.Sprintf("not proto %d", proto))
	case string:
		return append(m, fmt.Sprintf("not proto %s", proto))
	default:
		log.Fatalf("NotProtocol failed: required int or string: %T", p)
		return nil
	}
}

func (m MatchCriteria) SourceNet(net string) MatchCriteria {
	return append(m, fmt.Sprintf("ip from %s", net))
}

func (m MatchCriteria) NotSourceNet(net string) MatchCriteria {
	return append(m, fmt.Sprintf("ip from not %s", net))
}

func (m MatchCriteria) DestNet(net string) MatchCriteria {
	return append(m, fmt.Sprintf("to %s", net))
}

func (m MatchCriteria) NotDestNet(net string) MatchCriteria {
	return append(m, fmt.Sprintf("to not %s", net))
}

func (m MatchCriteria) SourceTable(name string) MatchCriteria {
	return append(m, fmt.Sprintf(`ip from table\(%s\)`, name))
}

func (m MatchCriteria) NotSourceTable(name string) MatchCriteria {
	return append(m, fmt.Sprintf(`ip from not table\(%s\)`, name))
}

func (m MatchCriteria) DestTable(name string) MatchCriteria {
	return append(m, fmt.Sprintf(`to table\(%s\)`, name))
}

func (m MatchCriteria) NotDestTable(name string) MatchCriteria {
	return append(m, fmt.Sprintf(`to not table\(%s\)`, name))
}

func (m MatchCriteria) TableNames() (tableNames []string) {
	re := regexp.MustCompile(`^table\(.*\)$`)
	for _, matchString := range []string(m) {
		words := strings.Split(matchString, " ")
		for i := range words {
			if re.MatchString(words[i]) {
				tableNames = append(tableNames, words[i])
			}
		}
	}
	return
}

func (m MatchCriteria) InInterface(iface string) MatchCriteria {
	return append(m, fmt.Sprintf("recv '%s'", iface))
}

func (m MatchCriteria) OutInterface(iface string) MatchCriteria {
	return append(m, fmt.Sprintf("xmit '%s'", iface))
}

func (m MatchCriteria) SourcePorts(port uint16) MatchCriteria {
	return append(m, fmt.Sprintf("src-port %d", port))
}

func (m MatchCriteria) DestPorts(port uint16) MatchCriteria {
	return append(m, fmt.Sprintf("dst-port %d", port))
}

func (m MatchCriteria) PacketDirection(direction string) MatchCriteria {
	return append(m, direction)
}

func (m MatchCriteria) ConntrackState(state string) MatchCriteria {
	return append(m, state)
}

// NotVerrevpath は、受信したインターフェースが送信元アドレスへの経路の出力インターフェースと
// 一致しないパケットに一致する（"not verrevpath"）。送信元の詐称の検出（RPF）に使う。
// ipfw(8): "For incoming packets, a routing table lookup is done on the packet's source address.
// If the interface on which the packet entered the system matches the outgoing interface for
// the route, the packet matches."
func (m MatchCriteria) NotVerrevpath() MatchCriteria {
	return append(m, "not verrevpath")
}

// RecordState は、このルールに一致したときに動的ルールを作る（"record-state :flowname"）。
// 動的ルールはプロトコル・送信元/宛先の IP とポートの組で、両方向の通信に一致する（ipfw(8)）。
// keep-state と異なり、このルール自身では check-state を行わない。
func (m MatchCriteria) RecordState(flowName string) MatchCriteria {
	return append(m, fmt.Sprintf("record-state :%s", flowName))
}

func (m MatchCriteria) SourcePortRanges(ports []*proto.PortRange) MatchCriteria {
	portsString := PortRangesToMultiport(ports)
	return append(m, fmt.Sprintf("src-port %s", portsString))
}

func (m MatchCriteria) NotSourcePortRanges(ports []*proto.PortRange) MatchCriteria {
	portsString := PortRangesToMultiport(ports)
	return append(m, fmt.Sprintf("not src-port %s", portsString))
}

func (m MatchCriteria) DestPortRanges(ports []*proto.PortRange) MatchCriteria {
	portsString := PortRangesToMultiport(ports)
	return append(m, fmt.Sprintf("src-port %s", portsString))
}

func (m MatchCriteria) NotDestPortRanges(ports []*proto.PortRange) MatchCriteria {
	portsString := PortRangesToMultiport(ports)
	return append(m, fmt.Sprintf("src-port %s", portsString))
}

func PortRangesToMultiport(ports []*proto.PortRange) string {
	portFragments := make([]string, len(ports))
	for i, port := range ports {
		if port.First == port.Last {
			portFragments[i] = fmt.Sprintf("%d", port.First)
		} else {
			portFragments[i] = fmt.Sprintf("%d:%d", port.First, port.Last)
		}
	}
	portsString := strings.Join(portFragments, ",")
	return portsString
}
