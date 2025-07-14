//go:build freebsd

package ipfw

import (
	"fmt"
	"log"
	"strings"
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
	return append(m, fmt.Sprintf("ip from table(%s)", name))
}

func (m MatchCriteria) NotSourceTable(name string) MatchCriteria {
	return append(m, fmt.Sprintf("ip from not table(%s)", name))
}

func (m MatchCriteria) DestTable(name string) MatchCriteria {
	return append(m, fmt.Sprintf("to table(%s)", name))
}

func (m MatchCriteria) NotDestTable(name string) MatchCriteria {
	return append(m, fmt.Sprintf("to not table(%s)", name))
}

func (m MatchCriteria) InInterface(iface string) MatchCriteria {
	return append(m, fmt.Sprintf("recv %s", iface))
}

func (m MatchCriteria) OutInterface(iface string) MatchCriteria {
	return append(m, fmt.Sprintf("xmit %s", iface))
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

